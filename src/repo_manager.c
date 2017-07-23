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
									 int *fd)
{
	int ret = -1;

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
	// to drain socket?
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

int git_lfs_repo_manager_service(int socket, const struct git_lfs_config *config)
{
	for(;;) {
		struct repo_cmd_header hdr;
		if(socket_read_fully(socket, &hdr, sizeof(hdr)) == sizeof(hdr) &&
		   hdr.magic == REPO_CMD_MAGIC)
		{
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
						git_lfs_repo_send_response(socket, REPO_CMD_ERROR, hdr.cookie, NULL, 0, NULL);
						continue;
					}
					
					switch(hdr.type) {
						default: break;
						case REPO_CMD_CHECK_OID_EXIST:
						{
							struct repo_check_oid_response resp;
							resp.exist = os_file_exists(path);
							if(git_lfs_repo_send_response(socket, REPO_CMD_CHECK_OID_EXIST, hdr.cookie, &resp, sizeof(resp), NULL) != sizeof(resp)) {
								continue;
							}
							break;
						}
						case REPO_CMD_GET_OID:
						{
							struct repo_oid_response resp;
							memset(&resp, 0, sizeof(resp));
							
							int fd = os_open_read(path);
							resp.successful = fd >= 0;
							if(resp.successful) {
								resp.content_length = os_file_size(path);
							}

							if(git_lfs_repo_send_response(socket, REPO_CMD_GET_OID, hdr.cookie, &resp, sizeof(resp), fd) != sizeof(resp)) {
								continue;
							}
							if(fd >= 0) os_close(fd);
							break;
						}
						case REPO_CMD_PUT_OID:
						{
							struct repo_oid_response resp;
							memset(&resp, 0, sizeof(resp));
							
							int fd = os_open_create(path, 0600);
							resp.successful = fd >= 0;
							if(git_lfs_repo_send_response(socket, REPO_CMD_PUT_OID, hdr.cookie, &resp, sizeof(resp), fd) != sizeof(resp)) {
								return -1;
							}
							if(fd >= 0) os_close(fd);
							break;
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
	}
	
	return 0;
}

int git_lfs_repo_check_oid_exist(int socket, const struct git_lfs_config *config, const struct git_lfs_repo *repo, const char *auth, unsigned char oid[32])
{
	struct repo_oid_cmd_data check_oid_req;
	check_oid_req.repo_id = repo->id;
	memcpy(check_oid_req.oid, oid, sizeof(check_oid_req.oid));
	struct repo_check_oid_response check_oid_resp;
	
	if(git_lfs_repo_send_request(socket, REPO_CMD_CHECK_OID_EXIST, &check_oid_req, sizeof(check_oid_req), &check_oid_resp, sizeof(check_oid_resp), NULL) < 0) {
		return -1;
	}
	
	return check_oid_resp.exist;
}

int git_lfs_repo_get_read_oid_fd(int socket, const struct git_lfs_config *config, const struct git_lfs_repo *repo, const char *auth, unsigned char oid[32], int *fd, long *size)
{
	struct repo_oid_cmd_data get_oid_req;
	get_oid_req.repo_id = repo->id;
	memcpy(get_oid_req.oid, oid, sizeof(get_oid_req.oid));
	struct repo_oid_response get_oid_resp;
	
	if(git_lfs_repo_send_request(socket,
								 REPO_CMD_GET_OID,
								 &get_oid_req, sizeof(get_oid_req),
								 &get_oid_resp, sizeof(get_oid_resp),
								 fd) < 0) {
		return -1;
	}
	
	*size = get_oid_resp.content_length;
	
	return get_oid_resp.successful ? 0 : -1;
}

int git_lfs_repo_get_write_oid_fd(int socket, const struct git_lfs_config *config, const struct git_lfs_repo *repo, const char *auth, unsigned char oid[32], int *fd)
{
	struct repo_oid_cmd_data put_oid_req;
	put_oid_req.repo_id = repo->id;
	memcpy(put_oid_req.oid, oid, sizeof(put_oid_req.oid));
	struct repo_oid_response put_oid_resp;
	
	if(git_lfs_repo_send_request(socket,
								 REPO_CMD_PUT_OID,
								 &put_oid_req, sizeof(put_oid_req),
								 &put_oid_resp, sizeof(put_oid_resp),
								 fd) < 0) {
		return -1;
	}
	
	return put_oid_resp.successful ? 0 : -1;
}

int git_lfs_repo_terminate_service(int socket)
{
	return git_lfs_repo_send_request(socket, REPO_CMD_TERMINATE, NULL, 0, NULL, 0, NULL);
}
