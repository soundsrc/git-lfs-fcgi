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
#include <string.h>
#include <signal.h>
#include "compat/queue.h"
#include "mongoose.h"
#include "os/sandbox.h"
#include "os/mutex.h"
#include "git_lfs_server.h"
#include "socket_io.h"
#include "config.h"

static os_mutex_t running_mutex;

static void int_handler(int sig)
{
	(void)sig;
	os_mutex_unlock(running_mutex);
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

struct thread_info
{
	const struct git_lfs_config *config;
};

static int handle_request(struct mg_connection *conn)
{
	struct mg_request_info *req = mg_get_request_info(conn);
	struct thread_info *info = (struct thread_info *)req->user_data;
	
	const struct git_lfs_repo *repo = NULL, *r;
	const char *end_point = NULL;
	SLIST_FOREACH(r, &info->config->repos, entries) {
		size_t repo_uri_len = strlen(r->uri);
		
		// found a match
		if(strncmp(r->uri, req->uri, repo_uri_len) == 0) {
			end_point = req->uri + repo_uri_len;
			repo = r;
			break;
		}
	}
	
	struct socket_io io;
	
	memset(&io, 0, sizeof(io));
	io.context = conn;
	io.read = io_mg_read;
	io.write = io_mg_write;
	io.write_http_status = io_mg_write_http_status;
	io.write_headers = io_mg_write_headers;
	io.printf = io_mg_printf;
	io.flush = io_mg_flush;
	
	if(repo) {
		git_lfs_server_handle_request(info->config, repo, &io, req->request_method, end_point);
	} else {
		git_lfs_write_error(&io, 404, "No repo at this URL.");
	}
	
	return 1;
}

int git_lfs_start_httpd(const struct git_lfs_config *config)
{
	//chroot("/var/empty")
	
	// only allow internet
	if(os_sandbox(SANDBOX_INET_SOCKET) < 0) {
		fprintf(stderr, "Sandbox failed.\n");
		return -1;
	}
	
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
	callbacks.begin_request = handle_request;
	
	struct thread_info info;
	info.config = config;
	
	struct mg_context *context = mg_start(&callbacks, &info, mg_options);
	if(!context) {
		fprintf(stderr,"Failed to start server.\n");
		return -1;
	}
	
	signal(SIGINT, int_handler);
	os_mutex_lock(running_mutex);
	os_mutex_lock(running_mutex);
	signal(SIGINT, SIG_DFL);
	mg_stop(context);

	return 0;
}
