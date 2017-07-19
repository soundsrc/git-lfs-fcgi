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
#include <fcgiapp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#if __OpenBSD__
#include <unistd.h>
#include <sys/param.h>
#endif
#include <getopt.h>
#include "compat/string.h"
#include "os/filesystem.h"
#include "os/mutex.h"
#include "os/threads.h"
#include "os/droproot.h"
#include "config.h"
#include "socket_io.h"
#include "git_lfs_server.h"

static os_mutex_t accept_mutex;

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
	int listening_socket;
};

static void *handle_request(void *data)
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
		
		if(!request_method || !document_uri) {
			git_lfs_write_error(&io, 500, "FCGI error.");
			continue;
		}

		struct git_lfs_repo *repo = NULL, *r;
		const char *end_point = NULL;
		SLIST_FOREACH(r, &info->config->repos, entries) {
			size_t repo_uri_len = strlen(r->uri);
			
			// found a match
			if(strncmp(r->uri, document_uri, repo_uri_len) == 0) {
				end_point = document_uri + repo_uri_len;
				repo = r;
				break;
			}
		}
		
		if(repo) {
			git_lfs_server_handle_request(info->config, repo, &io, request_method, end_point);
		} else {
			git_lfs_write_error(&io, 404, "No repositories found on path.");
		}

		FCGX_Finish_r(&request);
	}
	
	return NULL;
}

int main(int argc, char *argv[])
{
	int verbose = 0;
    int max_connections = 400;
	char config_path[4096] = "/etc/git-lfs-server/git-lfs.conf";

	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 'v' },
		{ "config", required_argument, 0, 'f' },
		{ 0, 0, 0, 0 }
	};
	
	accept_mutex = os_mutex_create();
	
	int opt_index;
	int c;
	while((c = getopt_long (argc, argv, "vp:", long_options, &opt_index)) >= 0)
	{
		switch(c) {
			case 'v':
				verbose++;
				break;
			case 'f':
				if(strlcpy(config_path, optarg, sizeof(config_path)) >= sizeof(config_path))
				{
					fprintf(stderr, "Invalid config path. Too long.\n");
					return -1;
				}
				break;
		}
	}
	
	struct git_lfs_config *config = git_lfs_load_config(config_path);
	if(!config) {
		fprintf(stderr, "Unable to load config.\n");
		return -1;
	}
	config->verbose = verbose;

	if(config->chroot_path)
	{
		if(!config->chroot_user || !config->chroot_group)
		{
			fprintf(stderr, "chroot_user and chroot_group must be specified when using chroot_path.\n");
			return -1;
		}
		
		if(os_droproot(config->chroot_path, config->chroot_user, config->chroot_group) < 0)
		{
			fprintf(stderr, "Failed to chroot and set user/group name.\n");
			return -1;
		}
	}

	if(verbose) {
		printf("Socket Path: %s\n", config->socket);
		if(config->chroot_path) {
			printf("Chroot: %s\n", config->chroot_path);
			printf("User: %s\n", config->chroot_user);
			printf("Group: %s\n", config->chroot_group);
		}
	}

	FCGX_Init();

    int listening_socket = FCGX_OpenSocket(config->socket, max_connections);
	if(listening_socket < 0) {
		fprintf(stderr, "Failed to create socket.");
		exit(1);
	}

	git_lfs_init();

#ifdef OpenBSD5_9
	if(strchr(socket_path, ':') != NULL) {
		// network socket fcgi
		if(pledge("stdio cpath rpath wpath inet", NULL) < 0) {
				fprintf(stderr, "pledge() error.\n");
				exit(-1);
		}
	} else {
		// unix socket fcgi
		if(pledge("stdio cpath rpath wpath unix", NULL) < 0) {
			fprintf(stderr, "pledge() error.\n");
			exit(-1);
		}
	}
#endif

	if(config->num_threads < 1 || config->num_threads > 256) {
		fprintf(stderr, "Invalid number of threads (%d) specified.\n", config->num_threads);
		return -1;
	}

	struct thread_info *thread_infos = (struct thread_info *)calloc(config->num_threads, sizeof(struct thread_info));

	for(int i = 1; i < config->num_threads; i++) {
		thread_infos[i].config = config;
		thread_infos[i].listening_socket = listening_socket;
		os_thread_create(handle_request, &thread_infos[i]);
	}

	thread_infos[0].config = config;
	thread_infos[0].listening_socket = listening_socket;
	handle_request(&thread_infos[0]);

	free(thread_infos);
	git_lfs_free_config(config);

	return 0;
}
