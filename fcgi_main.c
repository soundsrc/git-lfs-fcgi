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
#include <ctype.h>
#include <sys/stat.h>
#include <getopt.h>
#include "compat/string.h"
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
	char uri_root[512] = "";
    int max_connections = 400;

	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 'v' },
		{ "hostname", required_argument, 0, 0 },
		{ "port", required_argument, 0, 'p' },
		{ "object-dir", required_argument, 0, 0 },
		{ "socket", required_argument, 0, 0 },
		{ "uri-root", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	
	memset(&options, 0, sizeof(options));
	strlcpy(options.object_path, ".", sizeof(options.object_path));
	strlcpy(options.scheme, "http", sizeof(options.scheme));
	strlcpy(options.host, "localhost:8080", sizeof(options.scheme));
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
						printf("     --help              Display this help.\n");
						printf(" -v, --verbose           Be verbose, can be specified more than once.\n");
						printf("     --hostname=HOST     Hostname of this server (i.e. localhost:8080)\n");
						printf(" -p, --port=PORT         Port to listen (default: 8080)\n");
						printf("     --object-dir=PATH   Path to a directory where to store the objects (default: current directory)\n");
						printf("     --socket=PATH       Path to socket (overrides port).\n");
						printf("     --uri-root=PATH     Root path  (i.e. /git-lfs/)");
						return -1;
						break;
					case 2: /* hostname */
						if(strlcpy(options.host, optarg, sizeof(options.host)) >= sizeof(options.host))
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
						
						struct stat st;
						if(stat(options.object_path, &st) != 0)
						{
							fprintf(stderr, "Invalid object path.\n");
							return -1;
						}
						
						if(!S_ISDIR(st.st_mode))
						{
							fprintf(stderr, "%s: Path is not a valid directory.\n", options.object_path);
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
					case 6: /* uri-root */
					{
						if(strlcpy(uri_root, optarg, sizeof(uri_root)) >= sizeof(uri_root))
						{
							fprintf(stderr, "Invalid root uri path. Too long.\n");
							return -1;
						}
						
						// remove trailing slash
						int n = strlen(uri_root);
						while(n > 0 && uri_root[n - 1] == '/')
						{
							uri_root[--n] = 0;
						}
					}
						break;
						
				}
		}
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

		int uri_root_len = strlen(uri_root);
		if(strncmp(uri_root, document_uri, uri_root_len) == 0)
		{
			const char *end_point = document_uri + uri_root_len;
			git_lfs_server_handle_request(&options, &io, request_method, end_point);
		}

		FCGX_Finish_r(&request);
	}

	return 0;
}
