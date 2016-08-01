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
#include <string.h>
#include "compat/string.h"
#include "options.h"
#include "socket_io.h"
#include "git_lfs_server.h"

static void git_lfs_server_get_object_metadata(const struct options *options, const struct socket_io *io, const char *object_id)
{
	char object_path[PATH_MAX];
	FILE *fp;
	
	if(strlcpy(object_path, options->object_path, sizeof(object_path)) >= sizeof(object_path))
		goto toolong;
	if(strlcat(object_path, "/", sizeof(object_path)) >= sizeof(object_path))
		goto toolong;
	if(strlcat(object_path, object_id, sizeof(object_path)) >= sizeof(object_path))
		goto toolong;
	
	fp = fopen(object_path, "rb");
	if(!fp) {
		io->write_http_status(io->context, 404, "Not found");
		const char response[] =
		"Content-Type: application/vnd.git-lfs+json\r\n\r\n"
		"{\r\n"
		"\"message\": \"Not found\"\r\n"
		"}\r\n";
		io->write(io->context, response, sizeof(response));
		return;
	}
	

	fclose(fp);
	return;

toolong:
	fprintf(stderr, "error: Cannot retrive object because the object path is too long.\n");
}

void git_lfs_server_handle_request(const struct options *options, const struct socket_io *io, const char *method, const char *uri)
{
	if(strcmp(method, "GET") == 0)
	{
		// v1 /objects/[oid]
		if(strncmp(uri, "/objects/", 9) == 0)
		{
			git_lfs_server_get_object_metadata(options, io, uri + 9);
		}
	}
}
