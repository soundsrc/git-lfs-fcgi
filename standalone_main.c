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
#include "mongoose.h"

static struct mg_context *context = NULL;
static struct options options;
static int running = 1;

static void intHandler(int sig)
{
	running = 0;
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

static int handleRequest(struct mg_connection *conn)
{
	const struct mg_request_info *requestInfo = mg_get_request_info(conn);
	struct socket_io io;
	
	memset(&io, 0, sizeof(io));
	io.context = conn;
	io.read = io_mg_read;
	io.write = io_mg_write;
	io.write_http_status = io_mg_write_http_status;
	io.write_headers = io_mg_write_headers;
	io.printf = io_mg_printf;
	io.flush = io_mg_flush;

	git_lfs_server_handle_request(&options, &io, requestInfo->request_method, requestInfo->uri);

	return 1;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", required_argument, 0, 0 },
		{ "hostname", required_argument, 0, 0 },
		{ "port", required_argument, 0, 0 },
		{ "object-dir", required_argument, 0, 0 },
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

	
	struct mg_callbacks callbacks;
	char port_string[16];
	snprintf(port_string, sizeof(port_string), "%d", options.port);
	const char *mg_options[] = {
		"document_root", ".",
		"listening_ports", port_string,
		NULL
	};
	
	
	git_lfs_init();

	memset(&callbacks,0,sizeof(callbacks));
	callbacks.begin_request = handleRequest;
	context = mg_start(&callbacks, NULL, mg_options);
	if(!context) {
		fprintf(stderr,"Failed to start server.\n");
		return -1;
	}
	
	signal(SIGINT, intHandler);
	while(running) {
		usleep(10);
	}

	mg_stop(context);
	
	return 0;
}
