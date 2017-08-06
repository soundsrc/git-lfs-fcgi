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
#include <inttypes.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <openssl/sha.h>
#include "json.h"
#include "compat/string.h"
#include "compat/queue.h"
#include "compat/base64.h"
#include "os/filesystem.h"
#include "os/mutex.h"
#include "os/io.h"
#include "configuration.h"
#include "httpd.h"
#include "socket_io.h"
#include "oid_utils.h"
#include "repo_manager.h"
#include "mkdir_recusive.h"
#include "git_lfs_server.h"

typedef enum git_lfs_operation_type
{
	git_lfs_operation_unknown,
	git_lfs_operation_upload,
	git_lfs_operation_download
} git_lfs_operation;

void git_lfs_write_error(const struct socket_io *io, int error_code, const char *format, ...)
{
	char message[4096];
	va_list va;
	va_start(va, format);
	vsnprintf(message, sizeof(message), format, va);
	va_end(va);

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

static struct json_object *create_json_error(int error_code, const char *format, ...)
{
	char message[4096];
	va_list va;
	va_start(va, format);
	vsnprintf(message, sizeof(message), format, va);
	va_end(va);

	struct json_object *error = json_object_new_object();
	json_object_object_add(error, "code", json_object_new_int(error_code));
	json_object_object_add(error, "message", json_object_new_string(message));
	
	return error;
}

static void git_lfs_server_handle_batch(struct repo_manager *mgr,
										const struct git_lfs_config *config,
										const struct git_lfs_repo *repo,
										const struct socket_io *io)
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
	
	if(config->verbose >= 2)
	{
		printf("> %s\n", json_object_get_string(root));
	}
	
	struct json_object *operation;
	if(!json_object_object_get_ex(root, "operation", &operation) ||
	   !json_object_is_type(operation, json_type_string))
	{
		git_lfs_write_error(io, 400, "API error. Missing operation.");
		goto error0;
	}
	
	struct json_object *transfers;
	if(json_object_object_get_ex(root, "transfers", &transfers)) {
		int has_basic_transfer = 0;
		
		// transfers was specified
		struct array_list * transfers_array = json_object_get_array(transfers);
		if(!transfers_array) {
			git_lfs_write_error(io, 400, "API error. Transfers must be an array.");
			goto error0;
		}
		
		int n = array_list_length(transfers_array);
		for(int i = 0; i < n; ++i) {
			struct json_object *transfer_obj_type = array_list_get_idx(transfers_array, i);
			if(!json_object_is_type(transfer_obj_type, json_type_string)) {
				git_lfs_write_error(io, 400, "API error. Unable to parse transfer list.");
				goto error0;
			}
			const char *transfer_type = json_object_get_string(transfer_obj_type);
			if(0 == strcmp("basic", transfer_type)) {
				has_basic_transfer = 1;
				break;
			}
		}
		
		if(!has_basic_transfer) {
			git_lfs_write_error(io, 400, "Unable to handle any of the transfer types.");
			goto error0;
		}
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
		
		struct json_object *obj_info = json_object_new_object();
		json_object_object_add(obj_info, "oid", json_object_get(oid));
		json_object_object_add(obj_info, "size", json_object_get(size));
		json_object_object_add(obj_info, "authenticated", json_object_new_boolean(1));
		
		const char *oid_str = json_object_get_string(oid);
		if(!oid_str) {
			struct json_object *error = create_json_error(400, "OID is not a string.");
			json_object_object_add(obj_info, "error", error);
			json_object_array_add(output_objects, obj_info);
			continue;
		}

		uint8_t oid_hash[SHA256_DIGEST_LENGTH];
		if(oid_from_string(oid_str, oid_hash) < 0) {
			struct json_object *error = create_json_error(400, "OID (%s) is invalid.", oid_str);
			json_object_object_add(obj_info, "error", error);
			json_object_array_add(output_objects, obj_info);
			continue;
		}
		
		char expire_time[32];
		strftime(expire_time, sizeof(expire_time), "%FT%TZ", gmtime(&mgr->access_token_expire));

		char error_msg[128];
		switch(op) {
			case git_lfs_operation_upload:
			{
				int result = git_lfs_repo_check_oid_exist(mgr, config, repo, oid_hash, error_msg, sizeof(error_msg));
				if(result < 0) {
					struct json_object *error = create_json_error(400, "%s", error_msg);
					json_object_object_add(obj_info, "error", error);
					json_object_array_add(output_objects, obj_info);
					continue;
				}
				
				if(!result) // only add upload entry if file doesn't exist
				{
					char url[1024];

					// add upload url
					if(snprintf(url, sizeof(url), "%s/%s/upload/%s", config->base_url, repo->uri, oid_str) >= (long)sizeof(url)) {
						struct json_object *error = create_json_error(400, "Upload URL is too long.");
						json_object_object_add(obj_info, "error", error);
						json_object_array_add(output_objects, obj_info);
						continue;
					}

					struct json_object *upload = json_object_new_object();
					json_object_object_add(upload, "href", json_object_new_string(url));
					
					struct json_object *header = json_object_new_object();
					
					char auth_header[64];
					snprintf(auth_header, sizeof(auth_header), "Token %s", mgr->access_token);
					json_object_object_add(header, "Authorization", json_object_new_string(auth_header));
					json_object_object_add(upload, "header", header);

					json_object_object_add(upload, "expires_at", json_object_new_string(expire_time));
					
					struct json_object *actions = json_object_new_object();
					json_object_object_add(actions, "upload", upload);

					json_object_object_add(obj_info, "actions", actions);
				}

				break;
			}
			
			case git_lfs_operation_download:
			{
				int result = git_lfs_repo_check_oid_exist(mgr, config, repo, oid_hash, error_msg, sizeof(error_msg));
				if(result < 0) {
					struct json_object *error = create_json_error(400, "%s", error_msg);
					json_object_object_add(obj_info, "error", error);
					json_object_array_add(output_objects, obj_info);
					continue;
				}
				
				if(!result) {
					struct json_object *error = create_json_error(404, "Object (%s) does not exist.", oid_str);
					json_object_object_add(obj_info, "error", error);
					json_object_array_add(output_objects, obj_info);
					continue;
				}
				
				char download_url[1024];
				
				if(snprintf(download_url, sizeof(download_url), "%s/%s/download/%s", config->base_url, repo->uri, oid_str) >= (long)sizeof(download_url)) {
					struct json_object *error = create_json_error(400, "Download URL is too long.");
					json_object_object_add(obj_info, "error", error);
					json_object_array_add(output_objects, obj_info);
					continue;
				}
				
				struct json_object *download = json_object_new_object();
				json_object_object_add(download, "href", json_object_new_string(download_url));
				
				struct json_object *header = json_object_new_object();
				char auth_header[64];
				snprintf(auth_header, sizeof(auth_header), "Token %s", mgr->access_token);
				json_object_object_add(header, "Authorization", json_object_new_string(auth_header));
				json_object_object_add(download, "header", header);
				
				json_object_object_add(download, "expires_at", json_object_new_string(expire_time));

				struct json_object *actions = json_object_new_object();
				json_object_object_add(actions, "download", download);
				json_object_object_add(obj_info, "actions", actions);

				break;
			}
			
			default:
				break;
		}

		json_object_array_add(output_objects, obj_info);
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
	
	if(config->verbose >= 2)
	{
		printf("< %s\n", response_json);
	}
	
error1:
	json_object_put(output_objects);
	json_object_put(response_object);
error0:
	if(root) json_object_put(root);
	json_tokener_free(tokener);
}

static void git_lfs_download(struct repo_manager *mgr,
							 const struct git_lfs_config *config,
							 const struct git_lfs_repo *repo,
							 const struct socket_io *io,
							 const char *oid)
{
	uint8_t oid_bytes[SHA256_DIGEST_LENGTH];
	oid_from_string(oid, oid_bytes);

	int fd;
	long filesize;
	char error_msg[128];
	if(git_lfs_repo_get_read_oid_fd(mgr, config, repo, oid_bytes, &fd, &filesize, error_msg, sizeof(error_msg)) < 0) {
		git_lfs_write_error(io, 400, "%s", error_msg);
		return;
	}

	char content_length[64];
	snprintf(content_length, sizeof(content_length), "Content-Length: %ld", filesize);
	const char *headers[] = {
		"Content-Type: application/octet-stream",
		content_length
	};

	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));

	char buffer[4096];
	int n;

	while(filesize > 0 &&
		  (n = os_read(fd, buffer, sizeof(buffer) < filesize ? sizeof(buffer) : filesize)) > 0) {
		io->write(io->context, buffer, n);
		filesize -= n;
	}

	os_close(fd);
}

static void git_lfs_upload(struct repo_manager *mgr,
						   const struct git_lfs_config *config,
						   const struct git_lfs_repo *repo,
						   const struct socket_io *io,
						   const char *oid)
{
	uint8_t oid_bytes[SHA256_DIGEST_LENGTH];
	oid_from_string(oid, oid_bytes);
	
	uint32_t ticket;
	int fd;
	char error_msg[128];
	if(git_lfs_repo_get_write_oid_fd(mgr, config, repo, oid_bytes, &fd, &ticket, error_msg, sizeof(error_msg)) < 0) {
		git_lfs_write_error(io, 400, "%s", error_msg);
		return;
	}
	
	char buffer[4096];
	int n;
	while((n = io->read(io->context, buffer, sizeof(buffer))) > 0) {
		int actual = os_write(fd, buffer, n);
		if(actual < 0)
		{
			switch(errno)
			{
				case EDQUOT:
				case EFBIG:
					git_lfs_write_error(io, 425, "Insufficient space on storage.");
					os_close(fd);
					return;
				default:
					git_lfs_write_error(io, 500, "Write IO error.");
					os_close(fd);
					return;
			}
		}
	}

	os_close(fd);
	
	// commit
	if(git_lfs_repo_commit(mgr, ticket, error_msg, sizeof(error_msg)) < 0) {
		git_lfs_write_error(io, 400, "%s", error_msg);
		return;
	}

	io->write_http_status(io->context, 200, "OK");
	io->write_headers(io->context, NULL, 0);
}

void git_lfs_server_handle_request(struct repo_manager *mgr,
								   const struct git_lfs_config *config,
								   const struct git_lfs_repo *repo,
								   const struct socket_io *io,
								   const char *authorization_header,
								   const char *method,
								   const char *end_point,
								   struct query_param_list *params)
{
	if(config->verbose >= 1)
	{
		time_t now;
		char currentTime[64];
		
		time(&now);
		
		strftime(currentTime, sizeof(currentTime), "%d/%b/%Y:%H:%M:%S %z", localtime(&now));

		printf("%s %s %s\n", currentTime, method, end_point);
	}

	// authentication
	if(repo->enable_authentication)
	{
		// if authentication header is not passed
		if(!authorization_header)
		{
			char auth_header[512];
			const char *auth_realm = repo->name;
			if(repo->auth_realm)
			{
				auth_realm = repo->auth_realm;
			}
			
			if(snprintf(auth_header, sizeof(auth_header), "WWW-Authenticate: Basic realm=\"%s\"", auth_realm) >= sizeof(auth_header))
			{
				git_lfs_write_error(io, 500, "Authentication line is too long.");
				return;
			}
			
			const char *headers[] =
			{
				auth_header,
				"Content-Length: 0"
			};
			
			io->write_http_status(io->context, 401, "Unauthorized");
			io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));
			return;
		}
		
		char auth_line[256];
		if(strlcpy(auth_line, authorization_header, sizeof(auth_line)) >= sizeof(auth_line))
		{
			git_lfs_write_error(io, 500, "Authentication header is too long.");
			return;
		}
		
		char *p = auth_line;
		const char *auth_type = strsep(&p, " ");
		const char *auth_b64 = strsep(&p, "\r\n");
		
		if(!auth_type || !auth_b64)
		{
			git_lfs_write_error(io, 500, "Invalid authentication type.");
			return;
		}
		
		if(0 == strcmp("Token", auth_type))
		{
			strlcpy(mgr->access_token, auth_b64, sizeof(mgr->access_token));
		}
		else
		{
			if(0 != strcmp("Basic", auth_type))
			{
				git_lfs_write_error(io, 500, "Invalid authentication type.");
				return;
			}
			
			char decoded_b64[256];
			int n = b64_pton(auth_b64, (uint8_t *)decoded_b64, sizeof(decoded_b64));
			if(n < 0 || n >= sizeof(decoded_b64))
			{
				git_lfs_write_error(io, 500, "Invalid authentication. Authentication header error.");
				return ;
			}
			decoded_b64[n] = 0;
			
			char *user_pass = decoded_b64;
			const char *username = strsep(&user_pass, ":");
			char *password = strsep(&user_pass, ":");
			
			if(!username || !password)
			{
				git_lfs_write_error(io, 500, "Invalid authentication. Authentication header error.");
				return;
			}
			
			int result = git_lfs_repo_authenticate(mgr, config, repo, username, password, mgr->access_token, sizeof(mgr->access_token), &mgr->access_token_expire, NULL, 0);
			if(result <= 0)
			{
				git_lfs_write_error(io, 401, "Invalid credentials.");
				return;
			}
		}
	}

	if(strcmp(method, "GET") == 0)
	{
		if(strncmp(end_point, "/download/", 10) == 0) {
			git_lfs_download(mgr, config, repo, io, end_point + 10);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}
		
	} else if(strcmp(method, "PUT") == 0) {
		
		if(strncmp(end_point, "/upload/", 8) == 0) {
			git_lfs_upload(mgr, config, repo, io, end_point + 8);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}

	} else if(strcmp(method, "POST") == 0) {
		
		// v1 batch
		if(strcmp(end_point, "/objects/batch") == 0)
		{
			git_lfs_server_handle_batch(mgr, config, repo, io);
		} else {
			git_lfs_write_error(io, 501, "End point not supported.");
		}
		
	} else {
		git_lfs_write_error(io, 501, "HTTP method not supported.");
	}
}
