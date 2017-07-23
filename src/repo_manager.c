/*
 * Copyright (c) 2017 Sound <sound@sagaforce.com>
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
#include "repo_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "compat/queue.h"
#include "os/mutex.h"
#include "os/io.h"
#include "os/socket.h"
#include "os/filesystem.h"
#include "config.h"
#include "oid_utils.h"
#include "socket_utils.h"
#include "sha256.h"

static os_mutex_t lock = NULL;

static struct git_lfs_repo * find_repo_by_id(const struct git_lfs_config *config, int id)
{
	struct git_lfs_repo *repo;

	SLIST_FOREACH(repo, &config->repos, entries)
	{
		if(repo->id == id)
		{
			return repo;
		}
	}
	
	return NULL;
}

static int git_lfs_repo_send_request(int socket,
									 enum repo_cmd_type type,
									 const void *req_data, size_t req_size,
									 void *resp_data, size_t resp_size,
									 int *fd,
									 char *error_msg,
									 size_t error_msg_buf_size)
{
	int ret = -1;
	
	if(error_msg && error_msg_buf_size > 0) {
		*error_msg = 0;
	}

	if(!lock) lock = os_mutex_create();
	
	os_mutex_lock(lock);

	struct repo_cmd_header req_cmd, resp_cmd;
	req_cmd.magic = REPO_CMD_MAGIC;
	req_cmd.cookie = rand();
	req_cmd.type = type;
	
	// sends the request
	if(socket_write_fully(socket, &req_cmd, sizeof(req_cmd)) != sizeof(req_cmd)) goto fail;
	if(req_size > 0 && socket_write_fully(socket, req_data, req_size) != req_size) goto fail;
	
	// expect a reply
	if(socket_read_fully(socket, &resp_cmd, sizeof(resp_cmd)) != sizeof(resp_cmd)) goto fail;
	
	if(resp_cmd.magic != REPO_CMD_MAGIC ||
	   resp_cmd.cookie != req_cmd.cookie) {
		goto fail;
	}
	
	if(resp_cmd.type == REPO_CMD_ERROR) {
		struct repo_cmd_error_response err_resp;
		if(socket_read_fully(socket, &err_resp, sizeof(err_resp)) == sizeof(err_resp)) {
			if(error_msg) {
				err_resp.message[sizeof(err_resp.message) - 1] = 0;
				strlcpy(error_msg, err_resp.message, error_msg_buf_size);
			}
		}
		goto fail;
	}
	
	if(resp_size > 0) {
		if(fd) {
			if(os_recv_with_file_descriptor(socket, resp_data, resp_size, fd) != resp_size)
			{
				goto fail;
			}
		} else {
			if(socket_read_fully(socket, resp_data, resp_size) != resp_size) goto fail;
		}
	}
	
	ret = 0;
fail:
	os_mutex_unlock(lock);
	return ret;
}

static int git_lfs_repo_send_response(int socket,
									  enum repo_cmd_type type,
									  uint32_t cookie,
									  void *resp_data, size_t resp_size,
									  int *fd)
{
	struct repo_cmd_header hdr;
	hdr.magic = REPO_CMD_MAGIC;
	hdr.cookie = cookie;
	hdr.type = type;

	if(socket_write_fully(socket, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		return -1;
	}
	
	if(fd) {
		if(os_send_with_file_descriptor(socket, resp_data, resp_size, fd) != resp_size) {
			return -1;
		}
	} else {
		if(socket_write_fully(socket, resp_data, resp_size) != resp_size) {
			return -1;
		}
	}
	
	return 0;
}

static int git_lfs_repo_send_error_response(int socket, uint32_t cookie, const char *msg, ...)
{
	struct repo_cmd_error_response err_resp;
	
	va_list va;
	va_start(va, msg);
	vsnprintf(err_resp.message, sizeof(err_resp.message), msg, va);
	va_end(va);
	
	return git_lfs_repo_send_response(socket, REPO_CMD_ERROR, cookie, &err_resp, sizeof(err_resp), NULL);
}

int git_lfs_repo_manager_service(int socket, const struct git_lfs_config *config)
{
	for(;;) {
		struct repo_cmd_header hdr;
		if(socket_read_fully(socket, &hdr, sizeof(hdr)) != sizeof(hdr))
		{
			return - 1;
		}
		
		if(hdr.magic != REPO_CMD_MAGIC)
		{
			return -1;
		}
		
		switch(hdr.type) {
			case REPO_CMD_CHECK_OID_EXIST:
			case REPO_CMD_GET_OID:
			case REPO_CMD_PUT_OID:
			{
				struct repo_oid_cmd_data data;
				if(socket_read_fully(socket, &data, sizeof(data)) != sizeof(data)) {
					return -1;
				}
				
				struct git_lfs_repo *repo = find_repo_by_id(config, data.repo_id);
				if(!repo) {
					git_lfs_repo_send_response(socket, REPO_CMD_ERROR, hdr.cookie, NULL, 0, NULL);
					continue;
				}
			
				char path[PATH_MAX];
				char oid_str[65];
				oid_to_string(data.oid, oid_str);
				if(snprintf(path, sizeof(path), "%s/%.2s/%s", repo->root_dir, oid_str, oid_str) >= sizeof(path)) {
					git_lfs_repo_send_error_response(socket, hdr.cookie, "Unable to get object. Path is too long.");
					continue;
				}
				
				switch(hdr.type) {
					default: break;
					case REPO_CMD_CHECK_OID_EXIST:
					{
						struct repo_cmd_check_oid_response resp;
						memset(&resp, 0, sizeof(resp));

						resp.exist = os_file_exists(path);
						if(git_lfs_repo_send_response(socket, REPO_CMD_CHECK_OID_EXIST, hdr.cookie, &resp, sizeof(resp), NULL) < 0)
						{
							return -1;
						}
						break;
					}
					case REPO_CMD_GET_OID:
					{
						struct repo_cmd_get_oid_response resp;
						memset(&resp, 0, sizeof(resp));
						
						int fd = os_open_read(path);
						if(fd < 0)
						{
							git_lfs_repo_send_error_response(socket, hdr.cookie, "Object %s does not exist.", oid_str);
							continue;
						}

						resp.content_length = os_file_size(path);

						if(git_lfs_repo_send_response(socket, REPO_CMD_GET_OID, hdr.cookie, &resp, sizeof(resp), fd) < 0)
						{
							os_close(fd);
							return -1;
						}

						os_close(fd);
						break;
					}
					case REPO_CMD_PUT_OID:
					{
						struct repo_cmd_put_oid_response resp;
						memset(&resp, 0, sizeof(resp));
						
						// create the directory if it does not exist
						const char *dir_end = strrchr(path, '/');
						if(dir_end) {
							char dir[PATH_MAX];
							size_t len = dir_end - path;
							if(len + 1 < PATH_MAX) {
								memcpy(dir, path, len);
								dir[len] = 0;
							}
							
							if(!os_is_directory(dir)) {
								os_mkdir(dir, 0700);
							}
						}
						
						int fd = os_open_create(path, 0600);
						if(fd < 0) {
							git_lfs_repo_send_error_response(socket, hdr.cookie, "Object %s could not be created.", oid_str);
							continue;
						}
						
						resp.ticket = 0;
						if(git_lfs_repo_send_response(socket, REPO_CMD_PUT_OID, hdr.cookie, &resp, sizeof(resp), fd) < 0)
						{
							os_close(fd);
							return -1;
						}
						
						os_close(fd);
						break;
					}
					case REPO_CMD_COMMIT:
					{
#if 0
						if(config->verify_upload) {
							int fd = os_open_read("");
							int n;
							char buffer[4096];
							if(fd > 0) {
								SHA256_CTX ctx;
								SHA256_Init(&ctx);
								while((n = os_read(fd, buffer, sizeof(buffer))) > 0) {
									SHA256_Update(&ctx, buffer, n);
								}
								os_close(fd);

								unsigned char sha256[SHA256_DIGEST_LENGTH];
								unsigned char oid_hash[SHA256_DIGEST_LENGTH];
								SHA256_Final(sha256, &ctx);
								
								if(oid_from_string(oid, oid_hash) < 0) {
									return -1;
								}
								
								if(memcmp(oid_hash, sha256, SHA256_DIGEST_LENGTH) != 0) {
									return -1;
								}
							}
						}
#endif
					}
				}
			}
				break;
			case REPO_CMD_TERMINATE:
				git_lfs_repo_send_response(socket, REPO_CMD_TERMINATE, hdr.cookie, NULL, 0, NULL);
				return 0;
				break;
			default:
				break;
		}
	}
	
	return 0;
}

int git_lfs_repo_check_oid_exist(int socket,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 const char *auth,
								 unsigned char oid[32],
								 char *error_msg,
								 size_t error_msg_buf_len)
{
	struct repo_oid_cmd_data check_oid_req;

	check_oid_req.repo_id = repo->id;
	memcpy(check_oid_req.oid, oid, sizeof(check_oid_req.oid));

	struct repo_cmd_check_oid_response check_oid_resp;
	
	if(git_lfs_repo_send_request(socket,
								 REPO_CMD_CHECK_OID_EXIST,
								 &check_oid_req, sizeof(check_oid_req),
								 &check_oid_resp, sizeof(check_oid_resp),
								 NULL,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	return check_oid_resp.exist;
}

int git_lfs_repo_get_read_oid_fd(int socket,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 const char *auth,
								 unsigned char oid[32],
								 int *fd,
								 long *size,
								 char *error_msg,
								 size_t error_msg_buf_len)
{
	struct repo_oid_cmd_data request;
	struct repo_cmd_get_oid_response response;
	
	request.repo_id = repo->id;
	memcpy(request.oid, oid, sizeof(request.oid));

	if(git_lfs_repo_send_request(socket,
								 REPO_CMD_GET_OID,
								 &request, sizeof(request),
								 &response, sizeof(response),
								 fd,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	*size = response.content_length;
	
	return 0;
}

int git_lfs_repo_get_write_oid_fd(int socket,
								  const struct git_lfs_config *config,
								  const struct git_lfs_repo *repo,
								  const char *auth,
								  unsigned char oid[32],
								  int *fd,
								  char *error_msg,
								  size_t error_msg_buf_len)
{
	struct repo_oid_cmd_data request;
	struct repo_cmd_put_oid_response response;
	
	request.repo_id = repo->id;
	memcpy(request.oid, oid, sizeof(request.oid));
	
	if(git_lfs_repo_send_request(socket,
								 REPO_CMD_PUT_OID,
								 &request, sizeof(request),
								 &response, sizeof(response),
								 fd,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	return 0;
}

int git_lfs_repo_terminate_service(int socket)
{
	return git_lfs_repo_send_request(socket, REPO_CMD_TERMINATE, NULL, 0, NULL, 0, NULL, NULL, 0);
}
