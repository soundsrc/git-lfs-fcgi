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
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "json.h"
#include "compat/string.h"
#include "options.h"
#include "socket_io.h"
#include "git_lfs_server.h"

typedef enum git_lfs_operation_type
{
	git_lfs_operation_unknown,
	git_lfs_operation_upload,
	git_lfs_operation_download
} git_lfs_operation;

// oid's are hashes, only sha256 is defined
static int is_valid_oid(const char *oid)
{
	if(strnlen(oid, 65) != 64) return 0;
	
	for(int i = 0; i < 64; i++) {
		if(!((oid[i] >= '0' && oid[i] <= '9') ||
		   (oid[i] >='a' && oid[i] <= 'f')))
		{
			return 0;
		}
	}
	
	return 1;
}

static void git_lfs_write_error(const struct socket_io *io, int error_code, const char *message)
{
	const char *error_reason = "Unknown error";
	switch(error_code) {
		case 400: error_reason = "Bad Request"; break;
		case 404: error_reason = "Not Found"; break;
		case 422: error_reason = "Unprocessable Entity"; break;
		case 500: error_reason = "Internal Server Error"; break;
		case 501: error_reason = "Not Implemented"; break;
	}
	
	io->write_http_status(io->context, error_code, error_reason);
	
	json_object *error = json_object_new_object();
	json_object_object_add(error, "message", json_object_new_string(message));
	
	char content_length[64];
	const char *body = json_object_get_string(error);
	int length = strlen(body);
	
	snprintf(content_length, sizeof(content_length), "Content-Length: %d", length);
	const char *headers[] = {
		"Content-Type: application/vnd.git-lfs+json",
		content_length
	};
	
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));
	io->write(io->context, body, length);
	
	json_object_put(error);
}

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
			git_lfs_write_error(io, 400, "JSON parsing error.");
			goto error0;
		}
	}
	
	struct json_object *operation;
	if(!json_object_object_get_ex(root, "operation", &operation) ||
	   !json_object_is_type(operation, json_type_string))
	{
		git_lfs_write_error(io, 400, "API error. Missing operation.");
		goto error0;
	}
	
	
	git_lfs_operation op = git_lfs_operation_unknown;
	const char *operation_string = json_object_get_string(operation);
	if(strcmp(operation_string, "upload") == 0) {
		op = git_lfs_operation_upload;
	} else if(strcmp(operation_string, "download") == 0) {
		op = git_lfs_operation_download;
	} else {
		git_lfs_write_error(io, 400, "Unknown operation.");
		goto error0;
	}
	
	struct json_object *objects;
	if(!json_object_object_get_ex(root, "objects", &objects)
	   || !json_object_is_type(objects, json_type_array))
	{
		git_lfs_write_error(io, 400, "API error. Missing objects.");
		goto error0;
	}
	
	struct json_object *response_object = json_object_new_object();
	struct json_object *output_objects = json_object_new_array();
	
	struct array_list *obj_list = json_object_get_array(objects);
	int obj_count = array_list_length(obj_list);
	for(int i = 0; i < obj_count; i++) {
		struct json_object * obj = array_list_get_idx(obj_list, i);
		if(!json_object_is_type(obj, json_type_object)) {
			git_lfs_write_error(io, 400, "API error. Invalid object in stream.");
			goto error1;
		}
		
		struct json_object *oid, *size;
		if(!json_object_object_get_ex(obj, "oid", &oid) ||
		   !json_object_is_type(oid, json_type_string) ||
		   !json_object_object_get_ex(obj, "size", &size) ||
		   !json_object_is_type(size, json_type_int))
		{
			git_lfs_write_error(io, 400, "API error. Missing oid and size.");
			goto error1;
		}
		
		struct json_object *out = json_object_new_object();
		json_object_object_add(out, "oid", json_object_get(oid));
		json_object_object_add(out, "size", json_object_get(size));
		struct json_object *actions = json_object_new_object();
		
		switch(op) {
			case git_lfs_operation_upload:
			{
				char url[1024];

				// add upload url
				if(snprintf(url, sizeof(url), "%s://%s/upload/%s", options->scheme, options->host, json_object_get_string(oid)) >= (long)sizeof(url)) {
					git_lfs_write_error(io, 400, "Upload URL is too long.");
					json_object_put(actions);
					json_object_put(out);
					goto error1;
				}

				struct json_object *upload = json_object_new_object();
				json_object_object_add(upload, "href", json_object_new_string(url));
				json_object_object_add(actions, "upload", upload);
				
				// add verify url
				if(snprintf(url, sizeof(url), "%s://%s/verify", options->scheme, options->host) >= (long)sizeof(url)) {
					git_lfs_write_error(io, 400, "Upload URL is too long.");
					json_object_put(actions);
					json_object_put(out);
					goto error1;
				}
				
				struct json_object *verify = json_object_new_object();
				json_object_object_add(verify, "href", json_object_new_string(url));
				json_object_object_add(actions, "verify", verify);

				break;
			}
			
			case git_lfs_operation_download:
			{
				char download_url[1024];
				
				if(snprintf(download_url, sizeof(download_url), "%s://%s/download/%s", options->scheme, options->host, json_object_get_string(oid)) >= (long)sizeof(download_url)) {
					git_lfs_write_error(io, 400, "Download URL is too long.");
					json_object_put(actions);
					json_object_put(out);
					goto error1;
				}
				
				struct json_object *download = json_object_new_object();
				json_object_object_add(download, "href", json_object_new_string(download_url));
				json_object_object_add(actions, "download", download);
				break;
			}
			
			default:
				break;
		}
		
		json_object_object_add(out, "actions", actions);
		json_object_array_add(output_objects, out);
	}
	
	json_object_object_add(response_object, "objects", json_object_get(output_objects));

	const char *response_json = json_object_get_string(response_object);
	int length = strlen(response_json);
	char content_length[64];
	snprintf(content_length, sizeof(content_length), "Content-Length: %d", length);
	const char *headers[] = {
		"Content-Type: application/vnd.git-lfs+json",
		content_length
	};

	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));
	io->write(io->context, response_json, strlen(response_json));
	
error1:
	json_object_put(output_objects);
	json_object_put(response_object);
error0:
	if(root) json_object_put(root);
	json_tokener_free(tokener);
}

static void git_lfs_download(const struct options *options, const struct socket_io *io, const char *oid)
{
	char buffer[4096];
	int n;
	char object_path[PATH_MAX];
	
	if(!is_valid_oid(oid)) {
		git_lfs_write_error(io, 400, "Object ID is not valid.");
		return;
	}

	if(snprintf(object_path, sizeof(object_path), "%s/%.2s/%s", options->object_path, oid, oid) >= (long)sizeof(object_path))
	{
		git_lfs_write_error(io, 400, "Object path is too long.");
		return;
	}

	struct stat st;
	if(stat(object_path, &st) < 0)
	{
		switch(errno) {
			case ENOENT:
				git_lfs_write_error(io, 404, "Object was not found.");
				return;
			case EACCES:
				git_lfs_write_error(io, 403, "Permission to access object was denied.");
				return;
			default:
				git_lfs_write_error(io, 400, "Error accessing object.");
				return;
		}
		
		return;
	}

	FILE *fp = fopen(object_path, "rb");
	if(!fp) {
		git_lfs_write_error(io, 404, "Object was not found.");
		return;
	}

	char content_length[64];
	snprintf(content_length, sizeof(content_length), "Content-Length: %lld", st.st_size);
	const char *headers[] = {
		"Content-Type: application/octet-stream",
		content_length
	};

	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));

	while((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		io->write(io->context, buffer, n);
	}
	
	fclose(fp);
}

static void git_lfs_upload(const struct options *options, const struct socket_io *io, const char *oid)
{
	char buffer[4096];
	int n;
	char object_path[PATH_MAX], tmp_object_path[PATH_MAX];

	if(snprintf(object_path, sizeof(object_path), "%s/%.2s/", options->object_path, oid) >= (long)sizeof(object_path))
	{
		git_lfs_write_error(io, 400, "Object path is too long.");
		return;
	}

	if(access(object_path, F_OK) != 0)
	{
		mkdir(object_path, 0700);
	}

	if(strlcat(object_path, oid, sizeof(object_path)) >= sizeof(object_path))
	{
		git_lfs_write_error(io, 400, "Object path is too long.");
		return;
	}

	if(strlcpy(tmp_object_path, object_path, sizeof(tmp_object_path)) >= sizeof(tmp_object_path) ||
	   strlcat(tmp_object_path, "-tmp", sizeof(tmp_object_path)) >= sizeof(tmp_object_path))
	{
		git_lfs_write_error(io, 400, "Object path is too long.");
		return;
	}


	FILE *fp = fopen(tmp_object_path, "wb");
	if(!fp) {
		git_lfs_write_error(io, 400, "Failed to write to storage.");
		return;
	}

	while((n = io->read(io->context, buffer, sizeof(buffer))) > 0) {
		fwrite(buffer, 1, n, fp);
	}

	fclose(fp);

	// TODO: verify written data

	rename(tmp_object_path, object_path);

	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, NULL, 0);
}

static void git_lfs_verify(const struct options *options, const struct socket_io *io)
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
			git_lfs_write_error(io, 400, "JSON parsing error.");
			goto error0;
		}
	}
	
	struct json_object *oid, *size;
	if(!json_object_object_get_ex(root, "oid", &oid) ||
	   !json_object_is_type(oid, json_type_string) ||
	   !json_object_object_get_ex(root, "size", &size) ||
	   !json_object_is_type(size, json_type_int))
	{
		git_lfs_write_error(io, 400, "API error. Missing oid and size.");
		goto error0;
	}
	
	const char *oid_string = json_object_get_string(oid);
	if(!is_valid_oid(oid_string))
	{
		git_lfs_write_error(io, 400, "Invalid oid passed to verify.");
		goto error0;
	}

	char object_path[PATH_MAX];
	if(snprintf(object_path, sizeof(object_path), "%s/%.2s/%s", options->object_path, oid_string, oid_string) >= (long)sizeof(object_path))
	{
		git_lfs_write_error(io, 400, "Object path is too long.");
		goto error0;
	}
	
	struct stat st;
	if(stat(object_path, &st) != 0)
	{
		git_lfs_write_error(io, 404, "Object not found.");
		goto error0;
	}
	
	if(st.st_size != json_object_get_int(size))
	{
		git_lfs_write_error(io, 422, "Object size does not match the request.");
		goto error0;
	}
	
	const char *headers[] = {
		"Content-Type: application/vnd.git-lfs+json",
	};
	
	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));

error0:
	if(root) json_object_put(root);
	json_tokener_free(tokener);
}

void git_lfs_server_handle_request(const struct options *options, const struct socket_io *io, const char *method, const char *uri)
{
	if(strcmp(method, "GET") == 0)
	{
		if(strncmp(uri, "/download/", 10) == 0) {
			git_lfs_download(options, io, uri + 10);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}
		
	} else if(strcmp(method, "PUT") == 0) {
		
		if(strncmp(uri, "/upload/", 8) == 0) {
			git_lfs_upload(options, io, uri + 8);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}

	} else if(strcmp(method, "POST") == 0) {
		
		// v1 batch
		if(strcmp(uri, "/objects/batch") == 0)
		{
			git_lfs_server_handle_batch(options, io);
		} else if(strcmp(uri, "/verify") == 0) {
			git_lfs_verify(options, io);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}
		
	} else {
		git_lfs_write_error(io, 501, "HTTP method not supported.");
	}
}
