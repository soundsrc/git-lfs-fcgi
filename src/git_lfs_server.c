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
#include <assert.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <json-c/json.h>
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

#define JSON_OBJECT_CHECK(x, label) \
do {\
	if(!(x)) \
	{\
		fprintf(stderr, "%s:%d: JSON new returned NULL.\n", __FILE__, __LINE__); \
		git_lfs_write_error(io, 400, "Error when creating JSON response.");\
		goto label;\
	}\
} while(0)


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
		case 403: error_reason = "Forbidden"; break;
		case 404: error_reason = "Not Found"; break;
		case 422: error_reason = "Unprocessable Entity"; break;
		case 500: error_reason = "Internal Server Error"; break;
		case 501: error_reason = "Not Implemented"; break;
	}

	const char *body = "{\"message\":\"Unable to write error.\"}";
	
	json_object *error = json_object_new_object();
	if(error)
	{
		struct json_object *msg_obj = json_object_new_string(message);
		if(msg_obj)
		{
			json_object_object_add(error, "message", msg_obj);
			body = json_object_get_string(error);
		}
	}

	io->write_http_status(io->context, error_code, error_reason);
	char content_length[64];
	int length = strlen(body);
	
	snprintf(content_length, sizeof(content_length), "Content-Length: %d", length);
	const char *headers[] = {
		"Content-Type: application/vnd.git-lfs+json",
		content_length
	};

	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));
	io->write(io->context, body, length);
	io->flush(io->context);

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
	if(!error) return NULL;
	
	struct json_object *error_code_obj = json_object_new_int(error_code);
	if(!error_code_obj) goto error0;
	
	struct json_object *message_obj = json_object_new_string(message);
	if(!message_obj) goto error1;

	json_object_object_add(error, "code", error_code_obj);
	json_object_object_add(error, "message", message_obj);
	
	return error;
error1:
	json_object_put(error_code_obj);
error0:
	json_object_put(error);
	return NULL;
}

static struct json_object *parse_json_request(const struct socket_io *io)
{
	char buffer[4096];
	int n;
	json_tokener * tokener = json_tokener_new();
	struct json_object *request = NULL;

	while((n = io->read(io->context, buffer, sizeof(buffer))) > 0)
	{
		request = json_tokener_parse_ex(tokener, buffer, n);
		enum json_tokener_error err = json_tokener_get_error(tokener);
		if(err == json_tokener_success) break;
		if(err != json_tokener_continue)
		{
			json_tokener_free(tokener);
			return NULL;
		}
	}
	
	json_tokener_free(tokener);
	return request;
}

static void write_response_json(const struct git_lfs_config *config, struct socket_io *io, int code, const char *reason, struct json_object *response)
{
	const char *response_json = json_object_get_string(response);
	int length = strlen(response_json);
	char content_length[64];
	snprintf(content_length, sizeof(content_length), "Content-Length: %d", length);
	const char *headers[] =
	{
		"Content-Type: application/vnd.git-lfs+json",
		content_length
	};
	
	io->write_http_status(io->context, code, reason);
	io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));
	io->write(io->context, response_json, length);
	io->flush(io->context);

	if(config->verbose >= 2)
	{
		printf("< %s\n", response_json);
	}
}

static void git_lfs_server_handle_batch(struct repo_manager *mgr,
										const struct git_lfs_config *config,
										const struct git_lfs_repo *repo,
										struct socket_io *io)
{
	struct json_object *request = parse_json_request(io);
	if(!request)
	{
		git_lfs_write_error(io, 400, "Error while parsing request.");
		return;
	}
	
	struct json_object *operation;
	if(!json_object_object_get_ex(request, "operation", &operation) ||
	   !json_object_is_type(operation, json_type_string))
	{
		git_lfs_write_error(io, 400, "API error. Missing operation.");
		goto error0;
	}
	
	struct json_object *transfers;
	if(json_object_object_get_ex(request, "transfers", &transfers)) {
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
	if(strcmp(operation_string, "upload") == 0)
	{
		op = git_lfs_operation_upload;
	}
	else if(strcmp(operation_string, "download") == 0)
	{
		op = git_lfs_operation_download;
	}
	else
	{
		git_lfs_write_error(io, 400, "Unknown operation.");
		goto error0;
	}
	
	struct json_object *objects;
	if(!json_object_object_get_ex(request, "objects", &objects)
	   || !json_object_is_type(objects, json_type_array))
	{
		git_lfs_write_error(io, 400, "API error. Missing objects.");
		goto error0;
	}

	struct json_object *response = json_object_new_object();
	if(!response)
	{
		git_lfs_write_error(io, 400, "Failed to create response object.");
		goto error0;
	}
	
	struct json_object *output_objects = json_object_new_array();
	if(!output_objects)
	{
		git_lfs_write_error(io, 400, "Failed to create output object.");
		goto error1;
	}
	
	json_object_object_add(response, "objects", output_objects);
	
	struct array_list *obj_list = json_object_get_array(objects);
	int obj_count = array_list_length(obj_list);
	for(int i = 0; i < obj_count; i++)
	{
		struct json_object * obj = array_list_get_idx(obj_list, i);
		if(!json_object_is_type(obj, json_type_object))
		{
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
		JSON_OBJECT_CHECK(obj_info, error1);

		json_object_array_add(output_objects, obj_info);

		json_object_object_add(obj_info, "oid", json_object_get(oid));
		json_object_object_add(obj_info, "size", json_object_get(size));

		const char *oid_str = json_object_get_string(oid);
		if(!oid_str) {
			struct json_object *error = create_json_error(400, "OID is not a string.");
			JSON_OBJECT_CHECK(error, error1);
			json_object_object_add(obj_info, "error", error);
			continue;
		}

		uint8_t oid_hash[SHA256_DIGEST_LENGTH];
		if(oid_from_string(oid_str, oid_hash) < 0) {
			struct json_object *error = create_json_error(400, "OID (%s) is invalid.", oid_str);
			JSON_OBJECT_CHECK(error, error1);
			json_object_object_add(obj_info, "error", error);
			continue;
		}
		
		char expire_time[32];
		if(!strftime(expire_time, sizeof(expire_time), "%FT%TZ", gmtime(&mgr->access_token_expire)))
		{
			struct json_object *error = create_json_error(400, "Unable to format time string for timestamp %ld.", mgr->access_token_expire);
			JSON_OBJECT_CHECK(error, error1);
			json_object_object_add(obj_info, "error", error);
			continue;
		}

		char error_msg[128];
		switch(op) {
			case git_lfs_operation_upload:
			{
				int result = git_lfs_repo_check_oid_exist(mgr, config, repo, oid_hash, error_msg, sizeof(error_msg));
				if(result < 0)
				{
					struct json_object *error = create_json_error(400, "%s", error_msg);
					JSON_OBJECT_CHECK(error, error1);
					json_object_object_add(obj_info, "error", error);
					continue;
				}
				
				if(!result) // only add upload entry if file doesn't exist
				{
					char url[1024];

					// add upload url
					if(snprintf(url, sizeof(url), "%s/%s/upload/%s", repo->base_url ? repo->base_url : config->base_url, repo->uri, oid_str) >= (long)sizeof(url))
					{
						struct json_object *error = create_json_error(400, "Upload URL is too long.");
						JSON_OBJECT_CHECK(error, error1);
						json_object_object_add(obj_info, "error", error);
						continue;
					}

					struct json_object *actions = json_object_new_object();
					JSON_OBJECT_CHECK(actions, error1);
					json_object_object_add(obj_info, "actions", actions);

					struct json_object *upload = json_object_new_object();
					JSON_OBJECT_CHECK(upload, error1);

					json_object_object_add(actions, "upload", upload);

					struct json_object *href_obj = json_object_new_string(url);
					JSON_OBJECT_CHECK(href_obj, error1);
					json_object_object_add(upload, "href", href_obj);

					struct json_object *expire_obj = json_object_new_string(expire_time);
					JSON_OBJECT_CHECK(expire_obj, error1);
					json_object_object_add(upload, "expires_at", expire_obj);
				}

				break;
			}
			
			case git_lfs_operation_download:
			{
				int result = git_lfs_repo_check_oid_exist(mgr, config, repo, oid_hash, error_msg, sizeof(error_msg));
				if(result < 0)
				{
					struct json_object *error = create_json_error(400, "%s", error_msg);
					JSON_OBJECT_CHECK(error, error1);
					json_object_object_add(obj_info, "error", error);
					continue;
				}
				
				if(!result)
				{
					struct json_object *error = create_json_error(404, "Object (%s) does not exist.", oid_str);
					JSON_OBJECT_CHECK(error, error1);
					json_object_object_add(obj_info, "error", error);
					continue;
				}
				
				char download_url[1024];
				
				if(snprintf(download_url, sizeof(download_url), "%s/%s/download/%s", repo->base_url ? repo->base_url : config->base_url, repo->uri, oid_str) >= (long)sizeof(download_url))
				{
					struct json_object *error = create_json_error(400, "Download URL is too long.");
					JSON_OBJECT_CHECK(error, error1);
					json_object_object_add(obj_info, "error", error);
					continue;
				}
				
				struct json_object *actions = json_object_new_object();
				JSON_OBJECT_CHECK(actions, error1);
				json_object_object_add(obj_info, "actions", actions);

				struct json_object *download = json_object_new_object();
				JSON_OBJECT_CHECK(download, error1);
				json_object_object_add(actions, "download", download);
				
				struct json_object *download_obj = json_object_new_string(download_url);
				JSON_OBJECT_CHECK(download_obj, error1);
				json_object_object_add(download, "href", download_obj);

				struct json_object *expire_obj = json_object_new_string(expire_time);
				JSON_OBJECT_CHECK(expire_obj, error1);
				json_object_object_add(download, "expires_at", expire_obj);
				break;
			}
			
			default:
				break;
		}
	}

	write_response_json(config, io, 200, "Ok", response);

error1:
	json_object_put(response);
error0:
	json_object_put(request);
}

static void git_lfs_download(struct repo_manager *mgr,
							 const struct git_lfs_config *config,
							 const struct git_lfs_repo *repo,
							 const struct socket_io *io,
							 const char *oid,
							 int accepts_gzip)
{
	uint8_t oid_bytes[SHA256_DIGEST_LENGTH];
	if(oid_from_string(oid, oid_bytes) < 0)
	{
		git_lfs_write_error(io, 400, "Invalid object id.");
		return;
	}

	int fd;
	int compressed;
	long filesize;
	char error_msg[128];
	if(git_lfs_repo_get_read_oid_fd(mgr, config, repo, oid_bytes, &fd, &filesize, &compressed, error_msg, sizeof(error_msg)) < 0) {
		git_lfs_write_error(io, 400, "%s", error_msg);
		return;
	}

	unsigned char inBuf[131072];
	unsigned char outBuf[131072];
	// if object is compressed and server does not accept gzip, decompress it on the fly
	if (compressed && (!accepts_gzip || !repo->http_gzip))
	{
		int n, ret;
		z_stream strm;
		memset(&strm, 0, sizeof(strm));

		if (Z_OK != inflateInit2(&strm, 15 + 16))
		{
			git_lfs_write_error(io, 400, "inflateInit(): error initializing.");
			return;
		}

		const char *headers[] = {
			"Content-Type: application/octet-stream",
			"Transfer-Encoding: chunked"
		};

		io->write_http_status(io->context, 200, "OK");
		io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));

		do
		{
			n = os_read(fd, inBuf, sizeof(inBuf));
			if (n < 0)
			{
				assert(0 && "Read error from object.");
				goto inflate_error;
			}
			if (n == 0) break;

			strm.next_in = inBuf;
			strm.avail_in = n;
			do
			{
				strm.avail_out = sizeof(outBuf);
				strm.next_out = outBuf;

				ret = inflate(&strm, Z_NO_FLUSH);
				assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
				switch (ret) {
					case Z_NEED_DICT:
						ret = Z_DATA_ERROR;     /* and fall through */
					case Z_DATA_ERROR:
					case Z_MEM_ERROR:
						assert(0 && "Decompression error.");
						goto inflate_error;
				}

				int have = sizeof(outBuf) - strm.avail_out;
				if (have > 0)
				{
					io->printf(io->context, "%X\r\n", have);
					io->write(io->context, outBuf, have);
					io->write(io->context, "\r\n", 2);
				}
			} while (strm.avail_out == 0);

		} while (ret != Z_STREAM_END);
inflate_error:
		io->write(io->context, "0\r\n\r\n", 5);
		inflateEnd(&strm);
	}
	else
	{
		// on the fly compression
		if (accepts_gzip &&
			repo->http_gzip &&
			filesize >= repo->http_gzip_min_size &&
			!compressed)
		{
			int ret, flush;
			z_stream strm;
			memset(&strm, 0, sizeof(strm));

			if (Z_OK != deflateInit2(&strm, repo->http_gzip_level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY))
			{
				git_lfs_write_error(io, 400, "deflateInit2(): error initializing.");
				return;
			}

			const char *headers[] = {
				"Content-Type: application/octet-stream",
				"Transfer-Encoding: chunked",
				"Content-Encoding: gzip"
			};

			io->write_http_status(io->context, 200, "OK");
			io->write_headers(io->context, headers, sizeof(headers) / sizeof(headers[0]));

			do {
				int readBytes = os_read(fd, inBuf, sizeof(inBuf));
				if (readBytes < 0)
				{
					assert(0 && "Read error.");
					goto deflate_error;
				}

				flush = readBytes == 0 ? Z_FINISH : Z_NO_FLUSH;
				strm.avail_in = (uInt)readBytes;
				strm.next_in = inBuf;

				do
				{
					strm.avail_out = sizeof(outBuf);
					strm.next_out = outBuf;

					ret = deflate(&strm, flush);
					if (ret == Z_STREAM_ERROR)
					{
						assert(0 && "Deflate error.");
						goto deflate_error;
					}

					int have = sizeof(outBuf) - strm.avail_out;
					if (have > 0)
					{
						io->printf(io->context, "%X\r\n", have);
						io->write(io->context, outBuf, have);
						io->write(io->context, "\r\n", 2);
					}

				} while(strm.avail_out == 0);
				assert(strm.avail_in == 0);
			} while(flush != Z_FINISH);
			assert(ret == Z_STREAM_END);
deflate_error:
			deflateEnd(&strm);
			io->write(io->context, "0\r\n\r\n", 5);
		}
		else
		{
			char content_length[64];
			snprintf(content_length, sizeof(content_length), "Content-Length: %ld", filesize);
			const char *headers[] = {
				"Content-Type: application/octet-stream",
				content_length,
				"Content-Encoding: gzip" // only when (accepts_gzip && compressed)
			};

			io->write_http_status(io->context, 200, "OK");
			io->write_headers(io->context, headers, accepts_gzip && compressed ? 3 : 2);

			char buffer[4096];
			int n;

			while(filesize > 0 &&
				  (n = os_read(fd, buffer, sizeof(buffer) < filesize ? sizeof(buffer) : filesize)) > 0) {
				io->write(io->context, buffer, n);
				filesize -= n;
			}
		}
	}
	io->flush(io->context);

	os_close(fd);
}

static void git_lfs_upload(struct repo_manager *mgr,
						   const struct git_lfs_config *config,
						   const struct git_lfs_repo *repo,
						   const struct socket_io *io,
						   const char *oid)
{
	uint8_t oid_bytes[SHA256_DIGEST_LENGTH];
	if(oid_from_string(oid, oid_bytes) < 0)
	{
		git_lfs_write_error(io, 400, "Invalid object id.");
		return;
	}
	
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
	io->flush(io->context);
}

struct json_object *git_lfs_lock_info_to_json(struct repo_lock_info *lock_info)
{
	struct json_object *lock = json_object_new_object();
	if(!lock) return NULL;

	// set "id"
	char id_str[32];
	if(snprintf(id_str, sizeof(id_str), "%lld", lock_info->id) >= sizeof(id_str))
	{
		fprintf(stderr, "Truncation of id string.");
		goto error;
	}
	struct json_object *id_obj = json_object_new_string(id_str);
	if(!id_obj) goto error;
	json_object_object_add(lock, "id", id_obj);
	
	// set "path"
	struct json_object *path_obj = json_object_new_string(lock_info->path);
	if(!path_obj) goto error;
	json_object_object_add(lock, "path", path_obj);
	
	// set "locked_at"
	char lockedat_str[64];
	if(!strftime(lockedat_str, sizeof(lockedat_str), "%FT%TZ", gmtime(&lock_info->locked_at)))
	{
		fprintf(stderr, "Unable to write timestamp to buffer.");
		goto error;
	}
	struct json_object *lockedat_obj = json_object_new_string(lockedat_str);
	if(!lockedat_obj) goto error;
	json_object_object_add(lock, "locked_at", lockedat_obj);
	
	// set owner
	struct json_object *owner = json_object_new_object();
	if(!owner) goto error;
	json_object_object_add(lock, "owner", owner);
	
	// set name
	struct json_object *name = json_object_new_string(lock_info->username);
	if(!name) goto error;
	json_object_object_add(owner, "name", name);
	
	return lock;
error:
	json_object_put(lock);
	return NULL;
}

static void git_lfs_server_handle_create_lock(struct repo_manager *mgr,
											  const struct git_lfs_config *config,
											  const struct git_lfs_repo *repo,
											  struct socket_io *io)
{
	char error_msg[128];

	struct json_object *request = parse_json_request(io);
	if(!request)
	{
		git_lfs_write_error(io, 400, "Parsing request failed.");
		goto error0;
	}
	
	if(config->verbose >= 2)
	{
		printf("> %s\n", json_object_get_string(request));
	}
	
	struct json_object *path;
	if(!json_object_object_get_ex(request, "path", &path) || !json_object_is_type(path, json_type_string))
	{
		git_lfs_write_error(io, 400, "API error. Missing path");
		goto error0;
	}
	
	const char *path_str = json_object_get_string(path);
	
	struct repo_cmd_create_lock_response lock_info;
	if(git_lfs_repo_create_lock(mgr,
								repo,
								mgr->username,
								path_str,
								&lock_info,
								error_msg, sizeof(error_msg)) < 0)
	{
		git_lfs_write_error(io, 400, "%s", error_msg);
		goto error0;
	}
	
	struct json_object *response = json_object_new_object();
	JSON_OBJECT_CHECK(response, error0);
	
	struct json_object *lock = git_lfs_lock_info_to_json(&lock_info.lock);
	JSON_OBJECT_CHECK(lock, error1);

	json_object_object_add(response, "lock", lock);

	if(!lock_info.successful)
	{
		struct json_object *message = json_object_new_string("Lock exists");
		JSON_OBJECT_CHECK(message, error1);
		json_object_object_add(response, "message", message);
	}

	if(lock_info.successful)
	{
		write_response_json(config, io, 201, "Created", response);
	}
	else
	{
		write_response_json(config, io, 409, "Conflict", response);
	}
		
error1:
	json_object_put(response);
error0:
	json_object_put(request);
}

static void git_lfs_server_handle_list_locks(struct repo_manager *mgr,
											 const struct git_lfs_config *config,
											 const struct git_lfs_repo *repo,
											 struct socket_io *io,
											 const char *path,
											 int64_t *id,
											 int cursor,
											 int limit)
{
	struct repo_lock_info *lock_list;
	int next_cursor;
	char error_msg[128];
	int num_locks;

	if(git_lfs_repo_list_locks(mgr, repo, cursor, limit, path, id, &lock_list, &num_locks, &next_cursor, error_msg, sizeof(error_msg)) < 0)
	{
		git_lfs_write_error(io, 500, "%s", error_msg);
		return;
	}
	
	struct json_object *response = json_object_new_object();
	JSON_OBJECT_CHECK(response, error0);
	
	struct json_object *locks = json_object_new_array();
	JSON_OBJECT_CHECK(locks, error1);
	json_object_object_add(response, "locks", locks);

	for(int i = 0; i < num_locks; i++)
	{
		struct json_object *lock_json = git_lfs_lock_info_to_json(&lock_list[i]);
		JSON_OBJECT_CHECK(lock_json, error1);
		json_object_array_add(locks, lock_json);
	}
	
	if(next_cursor > 0)
	{
		char next_cursor_str[32];
		if(snprintf(next_cursor_str, sizeof(next_cursor_str), "%d", next_cursor) >= sizeof(next_cursor_str)) goto error1;
		struct json_object *next_cursor_obj = json_object_new_string(next_cursor_str);
		JSON_OBJECT_CHECK(next_cursor_str, error1);
		json_object_object_add(response, "next_cursor", next_cursor_obj);
	}

	write_response_json(config, io, 200, "Ok", response);

error1:
	json_object_put(response);
error0:
	free(lock_list);
}

static void git_lfs_server_handle_verify_list_locks(struct repo_manager *mgr,
											 const struct git_lfs_config *config,
											 const struct git_lfs_repo *repo,
											 struct socket_io *io)
{
	struct repo_lock_info *lock_list;
	int next_cursor;
	char error_msg[128];
	int num_locks;
	
	struct json_object *request = parse_json_request(io);
	if(!request)
	{
		git_lfs_write_error(io, 400, "Error parsing request.");
		return;
	}

	int cursor = 0;
	int limit = LIST_LOCKS_LIMIT;
	struct json_object *cursor_obj;
	if(json_object_object_get_ex(request, "cursor", &cursor_obj))
	{
		const char *cursor_str = json_object_get_string(cursor_obj);
		if(cursor_str && *cursor_str)
		{
			char *end_ptr;
			cursor = strtol(cursor_str, &end_ptr, 10);
			if(*end_ptr != 0)
			{
				cursor = 0;
			}
		}
	}
	
	struct json_object *limit_obj;
	if(json_object_object_get_ex(request, "limit", &limit_obj) &&
	   json_object_get_type(limit_obj) == json_type_int)
	{
		limit = json_object_get_int(limit_obj);
	}
	
	if(git_lfs_repo_list_locks(mgr, repo, cursor, limit, NULL, NULL, &lock_list, &num_locks, &next_cursor, error_msg, sizeof(error_msg)) < 0)
	{
		git_lfs_write_error(io, 500, "%s", error_msg);
		goto error0;
	}
	
	struct json_object *response = json_object_new_object();
	JSON_OBJECT_CHECK(response, error0);

	struct json_object *ours = json_object_new_array();
	JSON_OBJECT_CHECK(ours, error1);
	json_object_object_add(response, "ours", ours);
	
	struct json_object *theirs = json_object_new_array();
	JSON_OBJECT_CHECK(theirs, error1);
	json_object_object_add(response, "theirs", theirs);
	
	for(int i = 0; i < num_locks; i++)
	{
		struct json_object *lock_json = git_lfs_lock_info_to_json(&lock_list[i]);
		JSON_OBJECT_CHECK(lock_json, error1);

		if(0 == strcmp(lock_list[i].username, mgr->username))
		{
			json_object_array_add(ours, lock_json);
		}
		else
		{
			json_object_array_add(theirs, lock_json);
		}
	}
	
	if(next_cursor > 0)
	{
		char next_cursor_str[32];
		if(snprintf(next_cursor_str, sizeof(next_cursor_str), "%d", next_cursor) >= sizeof(next_cursor_str)) goto error1;
		struct json_object *next_cursor_obj = json_object_new_string(next_cursor_str);
		JSON_OBJECT_CHECK(next_cursor_str, error1);
		json_object_object_add(response, "next_cursor", next_cursor_obj);
	}

	write_response_json(config, io, 200, "Ok", response);
	
error1:
	json_object_put(response);
error0:
	free(lock_list);
}

static void git_lfs_server_handle_delete_lock(struct repo_manager *mgr,
											  const struct git_lfs_config *config,
											  const struct git_lfs_repo *repo,
											  struct socket_io *io,
											  int64_t id)
{
	char error_msg[128];
	
	struct json_object *request = parse_json_request(io);
	
	if(config->verbose >= 2)
	{
		printf("> %s\n", json_object_get_string(request));
	}
	
	int force = 0;
	struct json_object *force_obj;
	if(json_object_object_get_ex(request, "force", &force_obj) && json_object_is_type(force_obj, json_type_boolean))
	{
		force = json_object_get_boolean(force_obj);
	}
	
	struct repo_cmd_delete_lock_response delete_obj_response;
	if(git_lfs_repo_delete_lock(mgr,
								repo,
								mgr->username,
								id,
								force,
								&delete_obj_response,
								error_msg, sizeof(error_msg)) < 0)
	{
		git_lfs_write_error(io, 400, "%s", error_msg);
		goto error0;
	}
	
	struct json_object *response = json_object_new_object();
	JSON_OBJECT_CHECK(response, error0);
	
	struct json_object *lock = git_lfs_lock_info_to_json(&delete_obj_response.lock);
	JSON_OBJECT_CHECK(lock, error1);
	
	if(!delete_obj_response.successful)
	{
		git_lfs_write_error(io, 403, "Unable to delete lock. Not the owner.");
		goto error1;
	}
	
	write_response_json(config, io, 200, "Ok", response);

error1:
	json_object_put(response);
error0:
	json_object_put(request);
}


void git_lfs_server_handle_request(struct repo_manager *mgr,
								   const struct git_lfs_config *config,
								   const struct git_lfs_repo *repo,
								   struct socket_io *io,
								   const char *authorization_header,
								   int accepts_gzip,
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
		
		if(strlcpy(mgr->username, username, sizeof(mgr->username)) >= sizeof(mgr->username))
		{
			git_lfs_write_error(io, 401, "Username is too long.");
			return;
		}
	} else {
		char error_msg[256];
		if(git_lfs_repo_get_access_token(mgr, repo, mgr->access_token, sizeof(mgr->access_token), &mgr->access_token_expire, error_msg, sizeof(error_msg)) < 0)
		{
			git_lfs_write_error(io, 401, "%s", error_msg);
			return;
		}
	}

	if(strcmp(method, "GET") == 0)
	{
		if(strncmp(end_point, "/download/", 10) == 0)
		{
			git_lfs_download(mgr, config, repo, io, end_point + 10, accepts_gzip);
		}
		else if(strcmp(end_point, "/locks") == 0)
		{
			const char *path = NULL;
			int64_t id = -1;
			int cursor = 0;
			int limit = LIST_LOCKS_LIMIT;
			char *end_ptr;
			const char *str_val;
			
			path = get_query_param(params, "path");
			
			str_val = get_query_param(params, "id");
			if(str_val && *str_val)
			{
				id = strtoll(str_val, &end_ptr, 10);
				if(*end_ptr != 0) id = -1;
			}
			
			str_val = get_query_param(params, "cursor");
			if(str_val && *str_val)
			{
				cursor = strtoll(str_val, &end_ptr, 10);
				if(*end_ptr != 0) cursor = 0;
			}
			
			str_val = get_query_param(params, "limit");
			if(str_val && *str_val)
			{
				limit = strtoll(str_val, &end_ptr, 10);
				if(*end_ptr != 0) limit = LIST_LOCKS_LIMIT;
			}
			
			git_lfs_server_handle_list_locks(mgr, config, repo, io, path, id >= 0 ? &id : NULL, cursor, limit);
		}
		else
		{
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
		}
		else if(strcmp(end_point, "/locks") == 0)
		{
			git_lfs_server_handle_create_lock(mgr, config, repo, io);
		}
		else if(strcmp(end_point, "/locks/verify") == 0)
		{
			git_lfs_server_handle_verify_list_locks(mgr, config, repo, io);
		}
		else if(0 == strncmp(end_point, "/locks/", 7)) // starts with /locks
		{
			char delete_str[64];
			if(strlcpy(delete_str, end_point + 7, sizeof(delete_str)) >= sizeof(delete_str)) goto error;
			
			// attempt to extract /:id/unlock
			char *iter = delete_str;
			
			const char *id_str = strsep(&iter, "/");
			if(!id_str) goto error;
			
			const char *unlock_str = strsep(&iter, "/");
			if(!unlock_str) goto error;

			if(0 != strcmp(unlock_str, "unlock")) goto error;
			
			char *end_ptr;
			int64_t id = strtoll(id_str, &end_ptr, 10);
			if(*end_ptr != 0) goto error;
			
			git_lfs_server_handle_delete_lock(mgr, config, repo, io, id);
		}
		else
		{
			git_lfs_write_error(io, 501, "End point not supported.");
		}
		
	} else {
error:
		git_lfs_write_error(io, 501, "HTTP method not supported.");
	}
}

#undef JSON_OBJECT_CHECK
