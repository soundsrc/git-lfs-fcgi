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
    const char socket[] = ":9000";
    int maxConnections = 400;

	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", required_argument, 0, 0 },
		{ "hostname", required_argument, 0, 0 },
		{ "port", required_argument, 0, 0 },
		{ "object-dir", required_argument, 0, 0 },
		{ "socket", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	
	memset(&options, 0, sizeof(options));
	strlcpy(options.object_path, ".", sizeof(options.object_path));
	strlcpy(options.scheme, "http", sizeof(options.scheme));
	strlcpy(options.host, "localhost:8080", sizeof(options.scheme));
	options.port = 8080;
	
	int opt_index;
	int c;
	while((c = getopt_long (argc, argv, "vp:", long_options, &opt_index)) > 0)
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
				break;
			}
			default:
				switch(opt_index) {
					case 0: /* help */
						printf("usage: gif-lfs-server [options...]\n");
						printf("options:\n");
						printf("     --help              Display this help.\n");
						printf(" -v, --verbose           Be verbose, can be specified more than once.\n");
						printf("     --hostname=HOST     Hostname of this server (i.e. localhost:8080)\n");
						printf(" -p, --port=PORT         Port to listen (default: 8080)\n");
						printf("     --object-dir=PATH   Path to a directory where to store the objects (default: current directory)\n");
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
						
						if(!(st.st_mode & S_IFDIR))
						{
							fprintf(stderr, "%s: Path is not a valid directory.\n", options.object_path);
							return -1;
						}
					}
						break;
						
				}
		}
	}

	FCGX_Request request;

	FCGX_Init();

    int listeningSocket = FCGX_OpenSocket(socket, maxConnections);
	if(listeningSocket < 0) {
		fprintf(stderr, "Failed to create socket.");
		exit(1);
	}

	FCGX_InitRequest(&request, listeningSocket, 0);

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

		const char *requestMethod = FCGX_GetParam("REQUEST_METHOD", request.envp);
		const char *documentUri = FCGX_GetParam("DOCUMENT_URI", request.envp);
		const char *queryString = FCGX_GetParam("QUERY_STRING", request.envp);

		const char *endPoint = strrchr(documentUri, '/');
		if(endPoint) {
			git_lfs_server_handle_request(&options, &io, requestMethod, endPoint);
		}

		FCGX_Finish_r(&request);
	}

	return 0;
}
