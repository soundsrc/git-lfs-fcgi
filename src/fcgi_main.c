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
#include <sys/param.h>
#endif
#include <getopt.h>
#include "compat/string.h"
#include "os/filesystem.h"
#include "os/droproot.h"
#include "options.h"
#include "socket_io.h"
#include "git_lfs_server.h"

static struct options options;

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

int main(int argc, char *argv[])
{
    char socket_path[PATH_MAX] = ":8080";
    int max_connections = 400;
	char chroot_path[PATH_MAX] = "";
	char chroot_user[32] = "nobody";
	char chroot_group[32] = "nobody";

	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 'v' },
		{ "base-url", required_argument, 0, 0 },
		{ "port", required_argument, 0, 'p' },
		{ "object-dir", required_argument, 0, 0 },
		{ "socket", required_argument, 0, 0 },
		{ "chroot", required_argument, 0, 0 },
		{ "chroot-user", required_argument, 0, 0 },
		{ "chroot-group", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	
	memset(&options, 0, sizeof(options));
	strlcpy(options.object_path, ".", sizeof(options.object_path));
	strlcpy(options.base_url, "http://localhost:8080", sizeof(options.base_url));
	options.port = 8080;
	
	int opt_index;
	int c;
	while((c = getopt_long (argc, argv, "vp:", long_options, &opt_index)) >= 0)
	{
		switch(c) {
			case 'v':
				options.verbose++;
				break;
			case 'p':
			{
				int port = strtol(optarg, NULL, 10);
				if(port < 1024 || port > 65535)
				{
					fprintf(stderr, "Invalid port number.\n");
					return -1;
				}
				snprintf(socket_path, sizeof(socket_path), ":%d", port);
				break;
			}
			default:
				switch(opt_index) {
					default:
					case 0: /* help */
						printf("usage: gif-lfs-server [options...]\n");
						printf("options:\n");
						printf("     --help                Display this help.\n");
						printf(" -v, --verbose             Be verbose, can be specified more than once.\n");
						printf("     --base-url=URL        Base URL to the server (i.e. http://localhost:8080)\n");
						printf(" -p, --port=PORT           Port to listen (default: 8080)\n");
						printf("     --object-dir=PATH     Path to a directory where to store the objects (default: current directory)\n");
						printf("     --socket=PATH         Path to socket (overrides port).\n");
						printf("     --chroot=PATH         Path to chroot (root only).\n");
						printf("     --chroot-user=USER    Username for chroot (default: nobody).\n");
						printf("     --chroot-group=GROUP  Group for chroot (default: nobody).\n");
						return -1;
						break;
					case 2: /* base-url */
						if(strlcpy(options.base_url, optarg, sizeof(options.base_url)) >= sizeof(options.base_url))
						{
							fprintf(stderr, "Invalid hostname. Too long.\n");
							return -1;
						}
						break;
					case 4: /* object-dir */
					{
						if(strlcpy(options.object_path, optarg, sizeof(options.object_path)) >= sizeof(options.object_path))
						{
							fprintf(stderr, "Invalid object path. Too long.\n");
							return -1;
						}
						break;
					}
					case 5: /* socket */
					{
						if(strlcpy(socket_path, optarg, sizeof(socket_path)) >= sizeof(socket_path))
						{
							fprintf(stderr, "Invalid socket path. Too long.\n");
							return -1;
						}
					}
						break;
					case 6: /* chroot */
						if(strlcpy(chroot_path, optarg, sizeof(chroot_path)) >= sizeof(chroot_path))
						{
							fprintf(stderr, "Invalid chroot path. Too long.\n");
							return -1;
						}
						break;
					case 7: /* chroot-user */
						if(strlcpy(chroot_user, optarg, sizeof(chroot_user)) >= sizeof(chroot_user))
						{
							fprintf(stderr, "Invalid user name. Too long.\n");
							return -1;
						}
						break;
					case 8: /* chroot-group */
						if(strlcpy(chroot_group, optarg, sizeof(chroot_group)) >= sizeof(chroot_group))
						{
							fprintf(stderr, "Invalid group name. Too long.\n");
							return -1;
						}
						break;
				}
		}
	}
	
	if(chroot_path[0] != 0)
	{
		if(os_droproot(chroot_path, chroot_user, chroot_group) < 0)
		{
			fprintf(stderr, "Failed to chroot and set user/group name.\n");
			return -1;
		}
	}
	
	if(!os_is_directory(options.object_path))
	{
		fprintf(stderr, "%s: Path is not a valid directory.\n", options.object_path);
		return -1;
	}

	FCGX_Request request;

	FCGX_Init();

    int listening_socket = FCGX_OpenSocket(socket_path, max_connections);
	if(listening_socket < 0) {
		fprintf(stderr, "Failed to create socket.");
		exit(1);
	}

	FCGX_InitRequest(&request, listening_socket, 0);

	git_lfs_init();

#ifdef OpenBSD5_9
        if(pledge("stdio cpath unix inet", NULL) < 0) {
                fprintf(stderr, "pledge() error.\n");
                exit(-1);
        }
#endif

    while (FCGX_Accept_r(&request) == 0) {

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
		//const char *queryString = FCGX_GetParam("QUERY_STRING", request.envp);

		const char *uri_minus_scheme = strstr(options.base_url, "://");
		if(uri_minus_scheme) {
			uri_minus_scheme += 3;
		} else {
			uri_minus_scheme = options.base_url;
		}

		const char *base_doc_uri = strchr(uri_minus_scheme, '/');
		int uri_root_len = strlen(base_doc_uri);
		if(strncmp(base_doc_uri, document_uri, uri_root_len) == 0)
		{
			const char *end_point = document_uri + uri_root_len;
			if(*end_point != '/') --end_point;

			git_lfs_server_handle_request(&options, &io, request_method, end_point);
		}

		FCGX_Finish_r(&request);
	}

	return 0;
}
