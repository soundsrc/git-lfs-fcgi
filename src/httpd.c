/*
 * Copyright (c) 2016 Sound <sound@sagaforce.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "httpd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcgiapp.h>
#include "mongoose.h"
#include "compat/queue.h"
#include "compat/base64.h"
#include "compat/string.h"
#include "os/sandbox.h"
#include "os/mutex.h"
#include "os/threads.h"
#include "os/signal.h"
#include "htpasswd.h"
#include "git_lfs_server.h"
#include "repo_manager.h"
#include "socket_io.h"
#include "configuration.h"

static os_mutex_t running_mutex;
static os_mutex_t accept_mutex;

static void term_handler(int sig)
{
	(void)sig;
	os_mutex_unlock(running_mutex);
}

static void fcgi_term_handler(int sig)
{
	FCGX_ShutdownPending();
}

extern int mg_vprintf(struct mg_connection *conn, const char *fmt, va_list ap);

static int io_mg_read(void *context, void *buffer, int size)
{
	return mg_read((struct mg_connection *)context, buffer, size);
}

static int io_mg_write(void *context, const void *buffer, int size)
{
	return mg_write((struct mg_connection *)context, buffer, size);
}

static void io_mg_write_http_status(void *context, int code, const char *message)
{
	mg_printf((struct mg_connection *)context, "HTTP/1.1 %d %s\r\n", code, message);
}

static void io_mg_write_headers(void *context, const char * const *headers, int num_headers)
{
	for(int i = 0; i < num_headers; i++) {
		mg_printf((struct mg_connection *)context, "%s\r\n", headers[i]);
	}
	mg_write((struct mg_connection *)context, "\r\n", 2);
}

static int io_mg_printf(void *context, const char *format, ...)
{
	va_list va;
	int len;
	
	va_start(va, format);
	len = mg_vprintf((struct mg_connection *)context, format, va);
	va_end(va);
	
	return len;
}

static void io_mg_flush(void *context)
{
}

static int io_fcgi_read(void *context, void *buffer, int size)
{
	FCGX_Request *request = (FCGX_Request *)context;
	return FCGX_GetStr((char *)buffer, size, request->in);
}

static int io_fcgi_write(void *context, const void *buffer, int size)
{
	FCGX_Request *request = (FCGX_Request *)context;
	return FCGX_PutStr((const char *)buffer, size, request->out);
}

static void io_fcgi_write_http_status(void *context, int code, const char *message)
{
	FCGX_Request *request = (FCGX_Request *)context;
	FCGX_FPrintF(request->out, "Status: %d %s\r\n", code, message);
}

static void io_fcgi_write_headers(void *context, const char * const *headers, int num_headers)
{
	FCGX_Request *request = (FCGX_Request *)context;
	for(int i = 0; i < num_headers; i++) {
		FCGX_FPrintF(request->out, "%s\r\n", headers[i]);
	}
	FCGX_PutStr("\r\n", 2, request->out);
}

static int io_fcgi_printf(void *context, const char *format, ...)
{
	FCGX_Request *request = (FCGX_Request *)context;
	va_list va;
	int len;
	
	va_start(va, format);
	len = FCGX_VFPrintF(request->out, format, va);
	va_end(va);
	
	return len;
}

static void io_fcgi_flush(void *context)
{
	FCGX_Request *request = (FCGX_Request *)context;
	FCGX_FFlush(request->out);
}

struct thread_info
{
	const struct git_lfs_config *config;
	int listening_socket; // for fastcgi
	struct repo_manager *repo_mgr;
};

static void handle_request(struct thread_info *info,
						   struct socket_io *io,
						   const char *authentication,
						   const char *request_method,
						   const char *uri)
{
	const struct git_lfs_repo *repo = NULL, *r;
	const char *end_point = NULL;
	SLIST_FOREACH(r, &info->config->repos, entries) {
		size_t repo_uri_len = strlen(r->uri);
		
		// found a match
		if(strncmp(r->uri, uri, repo_uri_len) == 0) {
			end_point = uri + repo_uri_len;
			repo = r;
			break;
		}
	}
	
	if(repo) {
		git_lfs_server_handle_request(info->repo_mgr, info->config, repo, io, authentication, request_method, end_point);
	} else {
		git_lfs_write_error(io, 404, "No repo at this URL.");
	}
}

static int httpd_handle_request(struct mg_connection *conn)
{
	struct mg_request_info *req = mg_get_request_info(conn);
	struct thread_info *info = (struct thread_info *)req->user_data;
	
	struct socket_io io;
	
	memset(&io, 0, sizeof(io));
	io.context = conn;
	io.read = io_mg_read;
	io.write = io_mg_write;
	io.write_http_status = io_mg_write_http_status;
	io.write_headers = io_mg_write_headers;
	io.printf = io_mg_printf;
	io.flush = io_mg_flush;
	
	handle_request(info, &io, NULL, req->request_method, req->uri);
	
	return 1;
}

static void *fastcgi_handler_thread(void *data)
{
	FCGX_Request request;
	struct thread_info *info = (struct thread_info *)data;
	
	FCGX_InitRequest(&request, info->listening_socket, 0);
	
	for (;;) {
		
		os_mutex_lock(accept_mutex);
		int rc = FCGX_Accept_r(&request);
		os_mutex_unlock(accept_mutex);
		
		if(rc < 0) break;
		
		struct socket_io io;
		
		memset(&io, 0, sizeof(io));
		io.context = &request;
		io.read = io_fcgi_read;
		io.write = io_fcgi_write;
		io.write_http_status = io_fcgi_write_http_status;
		io.write_headers = io_fcgi_write_headers;
		io.printf = io_fcgi_printf;
		io.flush = io_fcgi_flush;
		
		const char *request_method = FCGX_GetParam("REQUEST_METHOD", request.envp);
		const char *document_uri = FCGX_GetParam("DOCUMENT_URI", request.envp);
		const char *authentication = FCGX_GetParam("HTTP_AUTHORIZATION", request.envp);

		if(!request_method || !document_uri) {
			git_lfs_write_error(&io, 500, "FCGI error.");
			continue;
		}

		handle_request(info, &io, authentication, request_method, document_uri);

		FCGX_Finish_r(&request);
	}
	
	return NULL;
}


int git_lfs_start_httpd(struct repo_manager *mgr, const struct git_lfs_config *config)
{
	if(!config->fastcgi_server) {
		running_mutex = os_mutex_create();

		char port_string[16];
		char num_threads_string[16];
		snprintf(port_string, sizeof(port_string), "%d", config->port);
		snprintf(num_threads_string, sizeof(num_threads_string), "%d", config->num_threads);
		
		const char *mg_options[] = {
			"listening_ports", port_string,
			"num_threads", num_threads_string,
			NULL
		};
		
		struct mg_callbacks callbacks;
		memset(&callbacks, 0, sizeof callbacks);
		callbacks.begin_request = httpd_handle_request;
		
		struct thread_info info;
		info.config = config;
		info.repo_mgr = mgr;
		
		struct mg_context *context = mg_start(&callbacks, &info, mg_options);
		if(!context) {
			fprintf(stderr,"Failed to start server.\n");
			return -1;
		}
		
		os_signal(SIGINT, term_handler);
		os_signal(SIGTERM, term_handler);
		os_mutex_lock(running_mutex);
		os_mutex_lock(running_mutex);
		os_mutex_unlock(running_mutex);

		os_signal(SIGINT, SIG_DFL);
		os_signal(SIGTERM, SIG_DFL);
		mg_stop(context);
		
		os_mutex_destroy(running_mutex);
	} else {
		accept_mutex = os_mutex_create();
		
		FCGX_Init();
		
		int saved_umask = os_umask(0);
		int listening_socket = FCGX_OpenSocket(config->fastcgi_socket, 400);
		if(listening_socket < 0) {
			fprintf(stderr, "Failed to create socket.");
			return -1;
		}
		os_umask(saved_umask);
		
		if(config->num_threads < 1 || config->num_threads > 256) {
			fprintf(stderr, "Invalid number of threads (%d) specified.\n", config->num_threads);
			return -1;
		}

		os_signal(SIGINT, fcgi_term_handler);
		os_signal(SIGTERM, fcgi_term_handler);
		
		struct thread_info *thread_infos = (struct thread_info *)calloc(config->num_threads, sizeof(struct thread_info));
		
		for(int i = 1; i < config->num_threads; i++) {
			thread_infos[i].config = config;
			thread_infos[i].listening_socket = listening_socket;
			thread_infos[i].repo_mgr = mgr;
			os_thread_create(fastcgi_handler_thread, &thread_infos[i]);
		}
		
		thread_infos[0].config = config;
		thread_infos[0].listening_socket = listening_socket;
		thread_infos[0].repo_mgr = mgr;
		fastcgi_handler_thread(&thread_infos[0]);
		
		os_signal(SIGINT, SIG_DFL);
		os_signal(SIGTERM, SIG_DFL);

		os_mutex_destroy(accept_mutex);
		free(thread_infos);
	}

	return 0;
}
