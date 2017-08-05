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

#include <time.h>
#include <stdint.h>
#include <stddef.h>

struct git_lfs_config;
struct git_lfs_repo;

struct repo_manager
{
	int socket;
	char access_token[16];
	time_t access_token_expire;
};

enum repo_cmd_type
{
	REPO_CMD_AUTH,
	REPO_CMD_CHECK_OID_EXIST,
	REPO_CMD_GET_OID,
	REPO_CMD_PUT_OID,
	REPO_CMD_COMMIT,
	REPO_CMD_TERMINATE,
	REPO_CMD_ERROR,
	REPO_CMD_CREATE_LOCK,
	REPO_CMD_LIST_LOCKS,
	REPO_CMD_RELEASE_LOCK
};

#define REPO_CMD_MAGIC 0xa733f97f

struct repo_cmd_header
{
	uint32_t magic;
	uint32_t cookie;
	char access_token[16];
	enum repo_cmd_type type;
};

struct repo_oid_cmd_data
{
	int repo_id;
	uint8_t oid[32];
};

struct repo_cmd_auth_request
{
	int repo_id;
	char username[33];
	char password[64];
};

struct repo_cmd_auth_response
{
	int success;
	time_t expire;
	char access_token[16];
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

// Create Lock
struct repo_cmd_create_lock_request
{
	int repo_id;
	char path[1024];
	char username[33];
};

struct repo_cmd_create_lock_response
{
	int successful;
	int64_t id;
	char username[33];
	char path[1024];
	time_t locked_at;
};

// List locks

struct repo_cmd_list_locks_request
{
	int repo_id;
	char path[1024];
	int64_t id;
	int cursor;
	int limit;
};

struct repo_cmd_list_lock_info
{
	int64_t id;
	char username[33];
	char path[1024];
	time_t locked_at;
};

struct repo_cmd_list_locks_response
{
	int num_locks;
	int next_cursor;
	struct repo_cmd_list_lock_info locks[];
};

struct repo_cmd_delete_lock_request
{
	int64_t id;
	int force;
};

struct repo_cmd_delete_lock_response
{
	int successful;
	int64_t id;
	char username[33];
	char path[1024];
	time_t locked_at;
};

struct repo_manager *repo_manager_create(int socket);
void repo_manager_free(struct repo_manager *mgr);

int git_lfs_repo_manager_service(struct repo_manager *mgr, const struct git_lfs_config *config);

int git_lfs_repo_authenticate(struct repo_manager *mgr,
							  const struct git_lfs_config *config,
							  const struct git_lfs_repo *repo,
							  const char *username,
							  const char *password,
							  char *access_token, size_t access_token_size,
							  time_t *expire,
							  char *error_msg,
							  size_t error_msg_buf_len);

int git_lfs_repo_check_oid_exist(struct repo_manager *mgr,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 unsigned char oid[32],
								 char *error_msg,
								 size_t error_msg_buf_len);

int git_lfs_repo_get_read_oid_fd(struct repo_manager *mgr,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 unsigned char oid[32],
								 int *fd,
								 long *size,
								 char *error_msg,
								 size_t error_msg_buf_len);

int git_lfs_repo_get_write_oid_fd(struct repo_manager *mgr,
								  const struct git_lfs_config *config,
								  const struct git_lfs_repo *repo,
								  unsigned char oid[32],
								  int *fd,
								  uint32_t *ticket,
								  char *error_msg,
								  size_t error_msg_buf_len);

int git_lfs_repo_commit(struct repo_manager *mgr,
						uint32_t ticket,
						char *error_msg,
						size_t error_msg_buf_len);

int git_lfs_repo_terminate_service(struct repo_manager *mgr);

#endif /* repo_manager_h */
