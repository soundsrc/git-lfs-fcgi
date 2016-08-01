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
#include <getopt.h>
#include "compat/string.h"
#include "options.h"
#include "socket_io.h"
#include "mongoose.h"

static struct mg_context *context = NULL;
static struct options options;
static int running = 1;

static void intHandler(int sig)
{
	running = 0;
}

static int io_mg_read(void *context, void *buffer, int size)
{
	return mg_read((struct mg_connection *)context, buffer, size);
}

static int io_mg_write(void *context, const void *buffer, int size)
{
	return mg_write((struct mg_connection *)context, buffer, size);
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
	io.flush = io_mg_flush;
	
	git_lfs_server_handle_request(&io, requestInfo->request_method, requestInfo->uri);
	
	return 1;
}

int main(int argc, char *argv[])
{
	struct mg_callbacks callbacks;
	const char *mg_options[] = {
		"document_root", ".",
		"listening_ports", "8080",
		NULL
	};

	memset(&options, 0, sizeof(options));
	if(strlcpy(options.object_path, ".", sizeof(options.object_path)) >= sizeof(options.object_path))
	{
		fprintf(stderr, "Object path is too long.\n");
		return -1;
	}
	
	
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
