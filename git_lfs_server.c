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
#include "json.h"
#include "compat/string.h"
#include "options.h"
#include "socket_io.h"
#include "git_lfs_server.h"

static struct json_object * git_lfs_server_get_object_metadata(const struct options *options, const struct socket_io *io, const char *object_id)
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
		fseek(fp, 0L, SEEK_END);
		long size = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		struct json_object *obj = json_object_new_object();
		json_object_object_add(obj, "oid", json_object_new_string(object_id));
		json_object_object_add(obj, "size", json_object_new_int64(size));
		
		struct json_object *links = json_object_new_object();
		struct json_object *self = json_object_new_object();
		
		char url[PATH_MAX];
		if(snprintf(url, sizeof(url), "%s://%s/objects/%s", options->scheme, options->host, object_id) >= sizeof(url)) {
			fprintf(stderr, "error: Cannot retrive object because the url is too long.\n");
			return NULL;
		}
		
		json_object_object_add(self, "href", json_object_new_string(url));
		struct json_object *download = json_object_new_object();
		
		if(snprintf(url, sizeof(url), "%s://%s/files/%s", options->scheme, options->host, object_id) >= sizeof(url)) {
			fprintf(stderr, "error: Cannot retrive object because the url is too long.\n");
			return NULL;
		}
		json_object_object_add(download, "href", json_object_new_string(url));
		
		json_object_object_add(links, "self", self);
		json_object_object_add(links, "download", download);
		json_object_object_add(obj, "_links", links);
		
		fclose(fp);
		
		return obj;
	}

toolong:
	fprintf(stderr, "error: Cannot retrive object because the object path is too long.\n");
	return NULL;
}

typedef enum git_lfs_operation_type
{
	git_lfs_operation_unknown,
	git_lfs_operation_upload
} git_lfs_operation;

static void git_lfs_server_handle_batch(const struct options *options, const struct socket_io *io)
{
	char buffer[4096];
	int n;
	json_tokener * tokener = json_tokener_new();
	struct json_object *root = NULL;
	
	while((n = io->read(io->context, buffer, sizeof(buffer))) > 0)
	{
		root = json_tokener_parse_ex(tokener, buffer, n);
		enum json_tokener_error err = json_tokener_get_error(tokener);
		if(err == json_tokener_success) break;
		if(err != json_tokener_continue) {
			io->write_http_status(io->context, 400, "Invalid operation.");
			goto error0;
		}
	}
	
	struct json_object *operation;
	if(!json_object_object_get_ex(root, "operation", &operation) ||
	   !json_object_is_type(operation, json_type_string))
	{
		io->write_http_status(io->context, 400, "Invalid operation.");
		goto error0;
	}
	
	
	git_lfs_operation op = git_lfs_operation_unknown;
	const char *operation_string = json_object_get_string(operation);
	if(strcmp(operation_string, "upload") == 0) {
		op = git_lfs_operation_upload;
	} else {
		io->write_http_status(io->context, 400, "Unknown operation.");
		goto error0;
	}
	
	struct json_object *objects;
	if(!json_object_object_get_ex(root, "objects", &objects)
	   || !json_object_is_type(objects, json_type_array))
	{
		io->write_http_status(io->context, 400, "Invalid operation.");
		goto error0;
	}
	
	struct json_object *response_object = json_object_new_object();
	struct json_object *output_objects = json_object_new_array();
	
	struct array_list *obj_list = json_object_get_array(objects);
	int obj_count = array_list_length(obj_list);
	for(int i = 0; i < obj_count; i++) {
		struct json_object * obj = array_list_get_idx(obj_list, i);
		if(!json_object_is_type(obj, json_type_object)) {
			io->write_http_status(io->context, 400, "Invalid operation.");
			goto error0;
		}
		
		struct json_object *oid, *size;
		if(!json_object_object_get_ex(obj, "oid", &oid) ||
		   !json_object_is_type(oid, json_type_string) ||
		   !json_object_object_get_ex(obj, "size", &size) ||
		   !json_object_is_type(size, json_type_int))
		{
			io->write_http_status(io->context, 400, "Invalid operation.");
			goto error0;
		}
		
		struct json_object *out = json_object_new_object();
		json_object_object_add(out, "oid", json_object_get(oid));
		json_object_object_add(out, "size", json_object_get(size));
		struct json_object *actions = json_object_new_object();
		
		if(op == git_lfs_operation_upload)
		{
			char upload_url[1024];

			if(snprintf(upload_url, sizeof(upload_url), "%s://%s/upload/%s", options->scheme, options->host, json_object_get_string(oid)) >= (long)sizeof(upload_url)) {
				io->write_http_status(io->context, 400, "Invalid operation.");
				goto error1;
			}

			struct json_object *upload = json_object_new_object();
			json_object_object_add(upload, "href", json_object_new_string(upload_url));
			json_object_object_add(actions, "upload", upload);
		}
		
		json_object_object_add(out, "actions", actions);
		
		json_object_array_add(output_objects, out);
	}
	
	json_object_object_add(response_object, "objects", json_object_get(output_objects));
	
	
	const char *response_json = json_object_get_string(response_object);
	const char headers[] = "Content-Type: application/vnd.git-lfs+json\r\n\r\n";
	io->write_http_status(io->context, 200, "Ok");
	io->write(io->context, headers, sizeof(headers) - 1);
	io->write(io->context, response_json, strlen(response_json));
	
error1:
	json_object_put(output_objects);
	json_object_put(response_object);
error0:
	if(root) json_object_put(root);
	json_tokener_free(tokener);
}

static void git_lfs_upload(const struct options *options, const struct socket_io *io, const char *oid)
{
	char buffer[4096];
	int n;
	
	while((n = io->read(io->context, buffer, sizeof(buffer))) > 0) {
		printf("%d\n", n);
	}
	
	io->write_http_status(io->context, 200, "Ok");
	io->write(io->context, "\r\n\r\n", 4);
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
	} else if(strcmp(method, "PUT") == 0) {
		
		if(strncmp(uri, "/upload/", 8) == 0) {
			git_lfs_upload(options, io, uri + 8);
		}

	} else if(strcmp(method, "POST") == 0) {
		
		// v1 batch
		if(strcmp(uri, "/objects/batch") == 0)
		{
			git_lfs_server_handle_batch(options, io);
		}
	}
}
