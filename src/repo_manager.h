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
#ifndef REPO_MANAGER_H
#define REPO_MANAGER_H

#include <stdint.h>
#include <stddef.h>

struct git_lfs_config;
struct git_lfs_repo;

enum repo_cmd_type
{
	REPO_CMD_CHECK_OID_EXIST,
	REPO_CMD_GET_OID,
	REPO_CMD_PUT_OID,
	REPO_CMD_COMMIT,
	REPO_CMD_TERMINATE,
	REPO_CMD_ERROR
};

#define REPO_CMD_MAGIC 0xa733f97f

struct repo_cmd_header
{
	uint32_t magic;
	uint32_t cookie;
	enum repo_cmd_type type;
};

struct repo_oid_cmd_data
{
	int repo_id;
	char auth[16];
	uint8_t oid[32];
};

// check oid response
struct repo_cmd_check_oid_response
{
	int exist;
};

struct repo_cmd_get_oid_response
{
	long content_length;
};

struct repo_cmd_put_oid_response
{
	uint32_t ticket;
};

struct repo_cmd_commit_request
{
	uint32_t ticket;
};

struct repo_cmd_error_response
{
	char message[128];
};

int git_lfs_repo_manager_service(int socket, const struct git_lfs_config *config);

int git_lfs_repo_check_oid_exist(int socket,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 const char *auth,
								 unsigned char oid[32],
								 char *error_msg,
								 size_t error_msg_buf_len);

int git_lfs_repo_get_read_oid_fd(int socket,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 const char *auth,
								 unsigned char oid[32],
								 int *fd,
								 long *size,
								 char *error_msg,
								 size_t error_msg_buf_len);

int git_lfs_repo_get_write_oid_fd(int socket,
								  const struct git_lfs_config *config,
								  const struct git_lfs_repo *repo,
								  const char *auth,
								  unsigned char oid[32],
								  int *fd,
								  char *error_msg,
								  size_t error_msg_buf_len);

int git_lfs_repo_terminate_service(int socket);

#endif /* repo_manager_h */
