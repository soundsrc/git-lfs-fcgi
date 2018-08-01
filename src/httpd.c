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
#include <ctype.h>
#include <fcgiapp.h>
#include "mongoose.h"
#include "compat/queue.h"
#include "compat/base64.h"
#include "compat/string.h"
#include "os/sandbox.h"
#include "os/mutex.h"
#include "os/threads.h"
#include "os/signal.h"
#include "os/filesystem.h"
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

const char *get_query_param(struct query_param_list *params, const char *key)
{
	struct query_param *param;
	SLIST_FOREACH(param, params, entry)
	{
		if(0 == strcmp(key, param->key))
		{
			return param->value;
		}
	}
	
	return NULL;
}

static void handle_request(struct thread_info *info,
						   struct socket_io *io,
						   const char *authentication,
						   const char *request_method,
						   const char *uri,
						   const char *query_string,
						   int accepts_gzip)
{
	// set some limits on HTTP input
	if(authentication && strnlen(authentication, 256) >= 256)
	{
		git_lfs_write_error(io, 413, "Authentication header too long.");
		return;
	}
	
	if(strnlen(request_method, 16) >= 16)
	{
		git_lfs_write_error(io, 413, "Invalid request method.");
		return;
	}
	
	if(strnlen(uri, 8192) >= 8192)
	{
		git_lfs_write_error(io, 413, "URI is too long.");
		return;
	}
	
	if(strnlen(query_string, 2048) >= 2048)
	{
		git_lfs_write_error(io, 413, "Query param is too long.");
		return;
	}

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
	
	struct query_param_list query_params;
	SLIST_INIT(&query_params);
	
	// query params parsing
	char *query_copy = strndup(query_string, 2048);
	if(!query_copy)
	{
		fprintf(stderr, "Unable to allocate memory for query params.");
		return;
	}

	char *iter = query_copy;
	
	char *pairs;
	while((pairs = strsep(&iter, "&")))
	{
		char *kviter = pairs;
		char *key = strsep(&kviter, "=");
		if(!key) continue;
		char *value = strsep(&kviter, "\r\n");
		if(!value) continue; // ignore keys without values, this is applicable to this app as we don't care about those
		
		struct query_param *param = calloc(1, sizeof *param);
		if(!param)
		{
			fprintf(stderr, "Unable to allocate memory for query params.");
			goto error0;
		}
		
		int key_len = strlen(key);
		int value_len = strlen(value);

		param->key = malloc(key_len + 1);
		if(!param->key)
		{
			fprintf(stderr, "Unable to allocate memory for query params.");
			goto error1;
		}
		
		if(mg_url_decode(key, key_len, param->key, key_len + 1, 0) < 0)
		{
			fprintf(stderr, "URL decode failed.");
			goto error2;
		}

		param->value = malloc(value_len + 1);
		if(!param->value)
		{
			fprintf(stderr, "Unable to allocate memory for query params.");
			goto error2;
		}
		
		if(mg_url_decode(value, value_len, param->value, value_len + 1, 0) < 0)
		{
			fprintf(stderr, "URL decode failed.");
			goto error3;
		}
		
		SLIST_INSERT_HEAD(&query_params, param, entry);
		
		continue;
error3:
		free(param->value);
error2:
		free(param->key);
error1:
		free(param);
		goto error0;
	}
	
	if(repo)
	{
		git_lfs_server_handle_request(info->repo_mgr, info->config, repo, io, authentication, accepts_gzip, request_method, end_point, &query_params);
	}
	else
	{
		git_lfs_write_error(io, 404, "No repo at this URL.");
	}
	
error0:
	free(query_copy);

	while(!SLIST_EMPTY(&query_params))
	{
		struct query_param *param = SLIST_FIRST(&query_params);
		SLIST_REMOVE_HEAD(&query_params, entry);
		free(param->value);
		free(param->key);
		free(param);
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
	
	const char *authentication = mg_get_header(conn, "Authorization");

	handle_request(info, &io, authentication, req->request_method, req->uri, req->query_string ? req->query_string : "", 0);
	
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
		const char *script_name = FCGX_GetParam("SCRIPT_NAME", request.envp);
		const char *authentication = FCGX_GetParam("HTTP_AUTHORIZATION", request.envp);
		const char *query_string = FCGX_GetParam("QUERY_STRING", request.envp);
		const char *accept_encoding = FCGX_GetParam("HTTP_ACCEPT_ENCODING", request.envp);
		int accepts_gzip = 0;
		if (accept_encoding)
		{
			char accept_encoding_copy[1024];
			if (strlcpy(accept_encoding_copy, accept_encoding, sizeof(accept_encoding_copy)) < sizeof(accept_encoding_copy))
			{
				char *p = accept_encoding_copy;
				char *encoding_weight;
				while((encoding_weight = strsep(&p, ",")))
				{
					char *q = encoding_weight;
					char *encoding = strsep(&q, ";");
					if (encoding)
					{
						while (*encoding && isspace(*encoding)) ++encoding;
						if (0 == strncmp(encoding, "gzip", 4) &&
							(0 == encoding[4] || isspace(encoding[4])))
						{
							accepts_gzip = 1;
							break;
						}
					}
				}
			}
		}
		
		if(!request_method || !script_name || !query_string)
		{
			git_lfs_write_error(&io, 500, "FCGI error.");
		}
		else
		{
			handle_request(info, &io, authentication, request_method, script_name, query_string, accepts_gzip);
		}

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
		
		if(os_sandbox(SANDBOX_INET_SOCKET) < 0)
		{
			fprintf(stderr, "Sandbox failed.\n");
			return -1;
		}

		struct mg_context *context = mg_start(&callbacks, &info, mg_options);
		if(!context) {
			fprintf(stderr, "Failed to start web server.\n");
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
			fprintf(stderr, "Failed to create FastCGI socket '%s'.", config->fastcgi_socket);
			return -1;
		}
		os_umask(saved_umask);
		
		if(config->num_threads < 1 || config->num_threads > 256) {
			fprintf(stderr, "Invalid number of threads (%d) specified. Must be >= 1 and < 256.\n", config->num_threads);
			return -1;
		}

		os_signal(SIGINT, fcgi_term_handler);
		os_signal(SIGTERM, fcgi_term_handler);
		
		// only allow internet
		if(os_sandbox(config->fastcgi_socket[0] != ':' ? SANDBOX_UNIX_SOCKET : SANDBOX_INET_SOCKET) < 0)
		{
			fprintf(stderr, "Sandbox failed.\n");
			return -1;
		}

		struct thread_info *thread_infos = (struct thread_info *)calloc(config->num_threads, sizeof(struct thread_info));
		if(!thread_infos)
		{
			fprintf(stderr, "Cannot allocate memory for threads.");
			return -1;
		}
		
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
