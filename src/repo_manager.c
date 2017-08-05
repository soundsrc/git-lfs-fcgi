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
#include <time.h>
#include <openssl/sha.h>
#include "sqlite3.h"
#include "compat/string.h"
#include "compat/queue.h"
#include "os/mutex.h"
#include "os/io.h"
#include "os/socket.h"
#include "os/filesystem.h"
#include "configuration.h"
#include "oid_utils.h"
#include "socket_utils.h"
#include "htpasswd.h"

static os_mutex_t lock = NULL;

struct upload_entry
{
	LIST_ENTRY(upload_entry) entries;

	uint32_t id;
	char tmp_path[PATH_MAX];
	uint8_t oid[32];
	const struct git_lfs_repo *repo;
	time_t expire;
};

static LIST_HEAD(upload_entry_list, upload_entry) upload_list;
static uint32_t next_upload_id = 0;

// access token lets one access files of the reps
struct git_lfs_access_token
{
	LIST_ENTRY(git_lfs_access_token) entries;
	
	char token[16];
	time_t expire;
	const struct git_lfs_repo *repo;
};

static LIST_HEAD(git_lfs_access_token_list, git_lfs_access_token) access_token_list;

static struct git_lfs_access_token *git_lfs_add_access_token(const struct git_lfs_repo *repo, time_t expires_at)
{
	static const char ch[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	struct git_lfs_access_token *access_token;

	// find existing access token
	LIST_FOREACH(access_token, &access_token_list, entries)
	{
		if(expires_at < access_token->expire)
		{
			return access_token;
		}
	}
	
	access_token = calloc(1, sizeof *access_token);
	access_token->expire = expires_at + 60;
	access_token->repo = repo;
	
	for(int i = 0; i < sizeof(access_token->token) - 1; ++i)
	{
		access_token->token[i] = ch[rand() % (sizeof(ch) - 1)];
	}
	access_token->token[sizeof(access_token->token) - 1] = 0;
	
	LIST_INSERT_HEAD(&access_token_list, access_token, entries);
	
	return access_token;
}

static void git_lfs_cleanup_access_tokens()
{
	struct git_lfs_access_token *access_token, *tmp;
	time_t now = time(NULL);
	LIST_FOREACH_SAFE(access_token, &access_token_list, entries, tmp)
	{
		if(now > access_token->expire) {
			LIST_REMOVE(access_token, entries);
			free(access_token);
		}
	}
}

static int git_lfs_verify_access_token(const char *access_token, int repo_id)
{
	struct git_lfs_access_token *token;
	LIST_FOREACH(token, &access_token_list, entries)
	{
		if(token->repo->id == repo_id &&
		   time(NULL) <= token->expire &&
		   0 == strncmp(token->token, access_token, sizeof(token->token)))
		{
			return 1;
		}
	}
	
	return 0;
}


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

struct repo_manager *repo_manager_create(int socket)
{
	struct repo_manager *mgr = calloc(1, sizeof *mgr);
	mgr->socket = socket;
	return mgr;
}

void repo_manager_free(struct repo_manager *mgr)
{
	free(mgr);
}

static int git_lfs_repo_send_request(struct repo_manager *mgr,
									 enum repo_cmd_type type,
									 const char *access_token,
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

	struct repo_cmd_header req_cmd;
	memset(&req_cmd, 0, sizeof(req_cmd));
	req_cmd.magic = REPO_CMD_MAGIC;
	req_cmd.cookie = rand();
	req_cmd.type = type;
	if(strlcpy(req_cmd.access_token, access_token, sizeof(req_cmd.access_token)) >= sizeof(req_cmd.access_token))
	{
		goto fail;
	}
	
	// sends the request
	if(socket_write_fully(mgr->socket, &req_cmd, sizeof(req_cmd)) != sizeof(req_cmd)) goto fail;
	if(req_size > 0 && socket_write_fully(mgr->socket, req_data, req_size) != req_size) goto fail;
	
	struct repo_cmd_header resp_cmd;
	// expect a reply
	if(socket_read_fully(mgr->socket, &resp_cmd, sizeof(resp_cmd)) != sizeof(resp_cmd)) goto fail;
	
	if(resp_cmd.magic != REPO_CMD_MAGIC ||
	   resp_cmd.cookie != req_cmd.cookie) {
		goto fail;
	}
	
	if(resp_cmd.type == REPO_CMD_ERROR) {
		struct repo_cmd_error_response err_resp;
		if(socket_read_fully(mgr->socket, &err_resp, sizeof(err_resp)) == sizeof(err_resp)) {
			if(error_msg) {
				err_resp.message[sizeof(err_resp.message) - 1] = 0;
				strlcpy(error_msg, err_resp.message, error_msg_buf_size);
			}
		}
		goto fail;
	}
	
	if(resp_size > 0) {
		if(fd) {
			if(os_recv_with_file_descriptor(mgr->socket, resp_data, resp_size, fd) != resp_size)
			{
				goto fail;
			}
		} else {
			if(socket_read_fully(mgr->socket, resp_data, resp_size) != resp_size) goto fail;
		}
	}
	
	ret = 0;
fail:
	os_mutex_unlock(lock);
	return ret;
}

static int git_lfs_repo_send_response(struct repo_manager *mgr,
									  enum repo_cmd_type type,
									  uint32_t cookie,
									  void *resp_data, size_t resp_size,
									  int *fd)
{
	struct repo_cmd_header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = REPO_CMD_MAGIC;
	hdr.cookie = cookie;
	hdr.type = type;

	if(socket_write_fully(mgr->socket, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		return -1;
	}
	
	if(fd) {
		if(os_send_with_file_descriptor(mgr->socket, resp_data, resp_size, *fd) != resp_size) {
			return -1;
		}
	} else {
		if(socket_write_fully(mgr->socket, resp_data, resp_size) != resp_size) {
			return -1;
		}
	}
	
	return 0;
}

static int git_lfs_repo_send_error_response(struct repo_manager *mgr, uint32_t cookie, const char *msg, ...)
{
	struct repo_cmd_error_response err_resp;
	
	va_list va;
	va_start(va, msg);
	vsnprintf(err_resp.message, sizeof(err_resp.message), msg, va);
	va_end(va);
	
	return git_lfs_repo_send_response(mgr, REPO_CMD_ERROR, cookie, &err_resp, sizeof(err_resp), NULL);
}

static int handle_cmd_auth(struct repo_manager *mgr, uint32_t cookie, const struct git_lfs_config *config)
{
	struct repo_cmd_auth_request request;
	struct repo_cmd_auth_response response;
	
	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));

	if(socket_read_fully(mgr->socket, &request, sizeof(request)) != sizeof(request))
	{
		return -1;
	}
	
	// check for unterminated username/password
	if(request.username[sizeof(request.username) - 1] != 0)
	{
		return -1;
	}
	
	if(request.password[sizeof(request.password) - 1] != 0)
	{
		return -1;
	}
	
	struct git_lfs_repo *repo = find_repo_by_id(config, request.repo_id);
	if(!repo) {
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid repo id.");
		return 0;
	}
	
	response.success = authenticate_user_with_password(repo->auth, request.username, request.password);
	if(response.success)
	{
		git_lfs_cleanup_access_tokens();
		struct git_lfs_access_token *token = git_lfs_add_access_token(repo, time(NULL) + 60);
		response.expire = token->expire;
		strlcpy(response.access_token, token->token, sizeof(response.access_token));
	}
	
	return git_lfs_repo_send_response(mgr, REPO_CMD_AUTH, cookie, &response, sizeof(response), NULL);
}

static int handle_cmd_check_oid(struct repo_manager *mgr, uint32_t cookie, const char *path)
{
	struct repo_cmd_check_oid_response resp;
	memset(&resp, 0, sizeof(resp));
	
	resp.exist = os_file_exists(path);
	if(git_lfs_repo_send_response(mgr, REPO_CMD_CHECK_OID_EXIST, cookie, &resp, sizeof(resp), NULL) < 0)
	{
		return -1;
	}
	
	return 0;
}

static int handle_cmd_get_oid(struct repo_manager *mgr, uint32_t cookie, const char *path, const char *oid_str)
{
	struct repo_cmd_get_oid_response resp;
	memset(&resp, 0, sizeof(resp));
	
	int fd = os_open_read(path);
	if(fd < 0)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Object %s does not exist.", oid_str);
		return 0;
	}
	
	resp.content_length = os_file_size(path);
	
	if(git_lfs_repo_send_response(mgr, REPO_CMD_GET_OID, cookie, &resp, sizeof(resp), &fd) < 0)
	{
		os_close(fd);
		return -1;
	}
	
	os_close(fd);
	return 0;
}

static int handle_cmd_put_oid(struct repo_manager *mgr,
							  uint32_t cookie,
							  struct git_lfs_repo *repo,
							  const uint8_t *oid,
							  const char *path)
{
	char oid_str[65];
	
	oid_to_string(oid, oid_str);

	struct repo_cmd_put_oid_response resp;
	memset(&resp, 0, sizeof(resp));
	
	// create the directory if it does not exist
	char tmp_dir[PATH_MAX];
	if(snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", repo->root_dir) >= sizeof(tmp_dir))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Repo root directory is too long.");
		return 0;
	}
	
	if(!os_is_directory(tmp_dir))
	{
		if(os_mkdir(tmp_dir, 0700) < 0)
		{
			git_lfs_repo_send_error_response(mgr, cookie, "Fail to create tmp directory. Repository root directory not accessible.");
			return 0;
		}
	}
	
	struct upload_entry *upload = calloc(1, sizeof *upload);
	upload->repo = repo;
	upload->id = next_upload_id++;
	upload->expire = time(NULL) + 7200;
	memcpy(upload->oid, oid, sizeof(upload->oid));
	
	if(snprintf(upload->tmp_path, sizeof(upload->tmp_path), "%s/XXXXXX", tmp_dir) >= sizeof(upload->tmp_path))
	{
		free(upload);
		git_lfs_repo_send_error_response(mgr, cookie, "Temp path is too long.");
		return 0;
	}
	
	int fd = os_mkstemp(upload->tmp_path);
	if(fd < 0) {
		free(upload);
		git_lfs_repo_send_error_response(mgr, cookie, "Object %s could not be created. Failed to create tmp file.", oid_str);
		return 0;
	}
	
	LIST_INSERT_HEAD(&upload_list, upload, entries);
	
	resp.ticket = upload->id;
	if(git_lfs_repo_send_response(mgr, REPO_CMD_PUT_OID, cookie, &resp, sizeof(resp), &fd) < 0)
	{
		os_close(fd);
		return -1;
	}
	
	os_close(fd);
	
	return 0;
}

static int handle_cmd_commit(struct repo_manager *mgr, const char *access_token, uint32_t cookie, const struct git_lfs_config *config)
{
	struct repo_cmd_commit_request request;
	if(socket_read_fully(mgr->socket, &request, sizeof(request)) != sizeof(request))
	{
		return -1;
	}

	struct upload_entry *up, *upload = NULL;
	LIST_FOREACH(up, &upload_list, entries)
	{
		if(up->id == request.ticket)
		{
			upload = up;
			break;
		}
	}

	if(!upload)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid upload ticket.");
		return 0;
	}
	
	if(!git_lfs_verify_access_token(access_token, upload->repo->id))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid access token.");
		return 0;
	}
	
	int ret = 0;
	
	char oid_str[65];
	char dest_path[PATH_MAX];
	
	oid_to_string(upload->oid, oid_str);
	
	if(snprintf(dest_path, sizeof(dest_path), "%s/%.2s/", upload->repo->root_dir, oid_str) >= sizeof(dest_path))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Object %s could not be created. Path too long.", oid_str);
		goto done;
	}
	
	if(!os_is_directory(dest_path))
	{
		if(os_mkdir(dest_path, 0700) < 0)
		{
			git_lfs_repo_send_error_response(mgr, cookie, "Object %s could not be created. Invalid path.", oid_str);
			goto done;
		}
	}
	
	if(strlcat(dest_path, oid_str + 2, sizeof(dest_path)) >= sizeof(dest_path))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Object %s could not be created. Path too long.", oid_str);
		goto done;
	}
	
	if(config->verify_upload)
	{
		int fd = os_open_read(upload->tmp_path);
		int n;
		char buffer[4096];
		if(fd < 0)
		{
			git_lfs_repo_send_error_response(mgr, cookie, "Unable to open written file for object %s.", oid_str);
			goto done;
		}
		
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		while((n = os_read(fd, buffer, sizeof(buffer))) > 0)
		{
			SHA256_Update(&ctx, buffer, n);
		}
		os_close(fd);
		
		unsigned char sha256[SHA256_DIGEST_LENGTH];
		SHA256_Final(sha256, &ctx);
		
		if(memcmp(upload->oid, sha256, SHA256_DIGEST_LENGTH) != 0)
		{
			char actual_hash_str[65];
			oid_to_string(sha256, actual_hash_str);
			git_lfs_repo_send_error_response(mgr, cookie, "Object %s failed verification. Unexpected hash %s.", oid_str, actual_hash_str);
			goto done;
		}
		
		if(os_rename(upload->tmp_path, dest_path) < 0)
		{
			git_lfs_repo_send_error_response(mgr, cookie, "Object %s failed rename.", oid_str);
			goto done;
		}
	}
	
	if(git_lfs_repo_send_response(mgr, REPO_CMD_COMMIT, cookie, NULL, 0, NULL) < 0)
	{
		ret = -1;
		goto done;
	}
	
done:
	LIST_REMOVE(upload, entries);
	os_unlink(upload->tmp_path);
	free(upload);
	
	return ret;
}

static sqlite3 *open_or_create_locks_db(struct git_lfs_repo *repo)
{
	char locks_path[1024];
	
	if(snprintf(locks_path, sizeof(locks_path), "%s/locks/", repo->root_dir) >= sizeof(locks_path))
	{
		return NULL;
	}
	
	if(!os_is_directory(locks_path))
	{
		if(os_mkdir(locks_path, 0700) < 0)
		{
			return NULL;
		}
	}
		
	if(strlcat(locks_path, "locks.db", sizeof(locks_path)) >= sizeof(locks_path))
	{
		return NULL;
	}
	
	int should_create = os_file_exists(locks_path);
	sqlite3 *db;
	if(SQLITE_OK != sqlite3_open(locks_path, &db))
	{
		goto error;
	}

	if(should_create)
	{
		char *err_msg;
		sqlite3_exec(db, "CREATE TABLE locks (id INTEGER PRIMARY KEY, path VARCHAR(1024) UNIQUE, locked_at INTEGER, owner VARCHAR(64));", NULL, NULL, &err_msg);
	}

	return db;
error:
	sqlite3_close(db);
	return -1;
}

static int handle_cmd_create_lock(struct repo_manager *mgr, const char *access_token, uint32_t cookie, const struct git_lfs_config *config)
{
	struct repo_cmd_create_lock_request request;
	struct repo_cmd_create_lock_response response;
	int ret = -1;

	memset(&response, 0, sizeof(response));
	if(socket_read_fully(mgr->socket, &request, sizeof(request)) != sizeof(request))
	{
		return -1;
	}
	
	struct git_lfs_repo *repo = find_repo_by_id(config, request.repo_id);
	if(!repo)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "No repo found at this URL.");
		return 0;
	}

	if(!git_lfs_verify_access_token(access_token, request.repo_id))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid access token.");
		return 0;
	}
	
	// request parameters be NULL initialized
	if(request.path[sizeof(request.path) - 1] != 0)
	{
		return -1;
	}
	
	if(request.username[sizeof(request.username) - 1] != 0)
	{
		return -1;
	}

	sqlite3 *db = open_or_create_locks_db(repo);
	if(!db)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Unable to open locks database.");
		return 0;
	}

	sqlite3_stmt *stmt;
	// check if lock exists already

	if(SQLITE_OK != sqlite3_prepare_v2(db, "SELECT (id, path, locked_at, owner) FROM locks WHERE path=?", -1, &stmt, NULL))
	{
		goto error0;
	}

	if(SQLITE_OK != sqlite3_bind_text(stmt, 0, request.path, -1, NULL)) goto error1;

	if(SQLITE_ROW == sqlite3_step(stmt))
	{
		// send lock exists response
		response.successful = 0;
		
		response.id = sqlite3_column_int64(stmt, 0);
		if(strlcpy(response.path, (const char *)sqlite3_column_text(stmt, 1), sizeof(response.path)) >= sizeof(response.path))
		{
			goto error1;
		}
		response.locked_at = sqlite3_column_int(stmt, 2);
		if(strlcpy(response.username, (const char *)sqlite3_column_text(stmt, 3), sizeof(response.username)) >= sizeof(response.username))
		{
			goto error1;
		}
		
		if(socket_write_fully(mgr->socket, &response, sizeof(response)) != sizeof(response))
		{
			goto error1;
		}

		ret = 0;
		goto error1;
	}
	sqlite3_finalize(stmt);
	
	if(SQLITE_OK != sqlite3_prepare_v2(db, "INSERT INTO locks VALUES(?,?,?,?)", -1, &stmt, NULL))
	{
		goto error1;
	}
	
	response.id = sqlite3_last_insert_rowid(db) + 1;
	if(strlcpy(response.path, (const char *)sqlite3_column_text(stmt, 1), sizeof(response.path)) >= sizeof(response.path))
	{
		goto error1;
	}
	response.locked_at = time(NULL);
	if(strlcpy(response.username, (const char *)sqlite3_column_text(stmt, 3), sizeof(response.username)) >= sizeof(response.username))
	{
		goto error1;
	}

	if(SQLITE_OK != sqlite3_bind_int64(stmt, 0, response.id)) goto error1;
	if(SQLITE_OK != sqlite3_bind_text(stmt, 1, request.path, -1, NULL)) goto error1;
	if(SQLITE_OK != sqlite3_bind_int(stmt, 2, response.locked_at)) goto error1;
	if(SQLITE_OK != sqlite3_bind_text(stmt, 3, request.username, -1, NULL)) goto error1;
	
	if(SQLITE_DONE != sqlite3_step(stmt))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Failed to create lock.");
		ret = 0;
		goto error1;
	}

	response.successful = 1;
	
	if(socket_write_fully(mgr->socket, &response, sizeof(response)) != sizeof(response))
	{
		goto error1;
	}

	ret = 0;
error1:
	sqlite3_finalize(stmt);
error0:
	sqlite3_close(db);

	return ret;
}

static int handle_list_locks(struct repo_manager *mgr, const char *access_token, uint32_t cookie, const struct git_lfs_config *config)
{
	int ret = -1;
	struct repo_cmd_list_locks_request request;

	if(socket_read_fully(mgr->socket, &request, sizeof(request)) != sizeof(request))
	{
		return -1;
	}
	
	if(request.path[sizeof(request.path) - 1] != 0)
	{
		return -1;
	}
	
	if(request.limit < 0 || request.cursor < 0)
	{
		return -1;
	}
	
	// internal limit
	if(request.limit > LIST_LOCKS_LIMIT)
	{
		request.limit = LIST_LOCKS_LIMIT;
	}
	
	struct git_lfs_repo *repo = find_repo_by_id(config, request.repo_id);
	if(!repo)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "No repo found at this URL.");
		return 0;
	}
	
	if(!git_lfs_verify_access_token(access_token, request.repo_id))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid access token.");
		return 0;
	}
	
	sqlite3 *db = open_or_create_locks_db(repo);
	if(!db)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Unable to open locks database.");
		goto error0;
	}

	char filter_query[512];
	char query[1024];
	
	filter_query[0] = 0;
	if(request.path[0] || request.id >= 0)
	{
		if(strlcpy(filter_query, "WHERE ", sizeof(filter_query)) >= sizeof(filter_query))
		{
			goto error0;
		}
	}
	
	if(request.path[0])
	{
		if(strlcpy(filter_query, "path=?", sizeof(filter_query)) >= sizeof(filter_query))
		{
			goto error0;
		}
	}
	
	if(request.id >= 0)
	{
		if(request.path[0])
		{
			if(strlcpy(filter_query, " AND ", sizeof(filter_query)) >= sizeof(filter_query))
			{
				goto error0;
			}
		}
		if(strlcpy(filter_query, "id=?", sizeof(filter_query)) >= sizeof(filter_query))
		{
			goto error0;
		}
	}
	
	if(snprintf(query, sizeof(query), "SELECT (id, path, locked_at, owner) FROM locks %s LIMIT %d,%d",
			 filter_query, request.cursor, request.limit) >= sizeof(query))
	{
		goto error0;
	}
	
	sqlite3_stmt *stmt;
	if(SQLITE_OK != sqlite3_prepare_v2(db, query, -1, &stmt, NULL))
	{
		goto error0;
	}
	
	int bind_index = 0;
	if(request.path[0])
	{
		if(SQLITE_OK != sqlite3_bind_text(stmt, bind_index++, request.path, -1, NULL))
		{
			goto error1;
		}
	}
	
	if(request.id)
	{
		if(SQLITE_OK != sqlite3_bind_int64(stmt, bind_index++, request.id))
		{
			goto error1;
		}
	}
	
	struct repo_cmd_list_locks_response *response = calloc(1, sizeof *response + LIST_LOCKS_LIMIT * sizeof(response->locks[0]));

	int row_count = 0;
	while(SQLITE_ROW == sqlite3_step(stmt))
	{
		if(row_count >= LIST_LOCKS_LIMIT)
		{
			goto error2; // should not happen, in theory
		}

		struct repo_cmd_list_lock_info *lock = &response->locks[row_count];
		lock->id = sqlite3_column_int64(stmt, 0);
		if(strlcpy(lock->path, (const char *)sqlite3_column_text(stmt, 1), sizeof(lock->path)) >= sizeof(lock->path))
		{
			goto error2;
		}
		lock->locked_at = sqlite3_column_int(stmt, 2);
		if(strlcpy(lock->username, (const char *)sqlite3_column_text(stmt, 3), sizeof(lock->username)) >= sizeof(lock->username))
		{
			goto error2;
		}
		row_count++;
	}
	
	response->num_locks = row_count;
	response->next_cursor = -1;
	if(row_count >= request.limit)
	{
		response->next_cursor = request.cursor + row_count;
	}

	if(git_lfs_repo_send_response(mgr, REPO_CMD_LIST_LOCKS, cookie, response, sizeof(*response) + row_count * sizeof(response->locks[0]), NULL) < 0)
	{
		goto error2;
	}

	ret = 0;
error2:
	free(response);
error1:
	sqlite3_finalize(stmt);
error0:
	sqlite3_close(db);

	return ret;
}

static int handle_delete_lock(struct repo_manager *mgr, const char *access_token, uint32_t cookie, const struct git_lfs_config *config)
{
	int ret = -1;
	struct repo_cmd_delete_lock_request request;
	
	if(socket_read_fully(mgr->socket, &request, sizeof(request)) != sizeof(request))
	{
		return -1;
	}
	
	if(request.username[sizeof(request.username) - 1] != 0)
	{
		return -1;
	}
	
	struct git_lfs_repo *repo = find_repo_by_id(config, request.repo_id);
	if(!repo)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "No repo found at this URL.");
		return 0;
	}
	
	if(!git_lfs_verify_access_token(access_token, request.repo_id))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Invalid access token.");
		return 0;
	}
	
	sqlite3 *db = open_or_create_locks_db(repo);
	if(!db)
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Unable to open locks database.");
		goto error0;
	}
	
	sqlite3_stmt *stmt;
	struct repo_cmd_delete_lock_response response;
	memset(&response, 0, sizeof(response));

	// get info about the lock first
	if(SQLITE_OK != sqlite3_prepare_v2(db, "SELECT (id, path, locked_at, owner) FROM locks WHERE id=?", -1, &stmt, NULL))
	{
		goto error0;
	}
	
	if(SQLITE_OK != sqlite3_bind_int64(stmt, 0, request.id))
	{
		goto error1;
	}
	
	if(SQLITE_ROW != sqlite3_step(stmt))
	{
		git_lfs_repo_send_error_response(mgr, cookie, "Lock does not exist.");
		goto error1;
	}
	
	response.id = sqlite3_column_int64(stmt, 0);
	if(strlcpy(response.path, (const char *)sqlite3_column_text(stmt, 1), sizeof(response.path)) >= sizeof(response.path))
	{
		goto error1;
	}
	response.locked_at = sqlite3_column_int(stmt, 2);
	if(strlcpy(response.username, (const char *)sqlite3_column_text(stmt, 3), sizeof(response.username)) >= sizeof(response.username))
	{
		goto error1;
	}

	sqlite3_finalize(stmt);

	// prepare to delete the lock
	
	if(request.force)
	{
		if(SQLITE_OK != sqlite3_prepare_v2(db, "DELETE locks WHERE id=?", -1, &stmt, NULL))
		{
			goto error0;
		}
		
		if(SQLITE_OK != sqlite3_bind_int64(stmt, 0, request.id))
		{
			goto error1;
		}
	}
	else
	{
		if(SQLITE_OK != sqlite3_prepare_v2(db, "DELETE locks WHERE id=? AND owner=?", -1, &stmt, NULL))
		{
			goto error0;
		}

		if(SQLITE_OK != sqlite3_bind_int64(stmt, 0, request.id))
		{
			goto error1;
		}
		
		if(SQLITE_OK != sqlite3_bind_text(stmt, 1, request.username, -1, NULL))
		{
			goto error1;
		}
	}

	response.successful = SQLITE_ROW == sqlite3_step(stmt) ? 1 : 0;
	
	if(git_lfs_repo_send_response(mgr, REPO_CMD_LIST_LOCKS, cookie, &response, sizeof(response), NULL) < 0)
	{
		goto error1;
	}

	ret = 0;
error1:
	sqlite3_finalize(stmt);
error0:
	sqlite3_close(db);
	
	return ret;
}

int git_lfs_repo_manager_service(struct repo_manager *mgr, const struct git_lfs_config *config)
{
	LIST_INIT(&upload_list);
	LIST_INIT(&access_token_list);

	int ret = -1;
	time_t last_clean = 0;
	for(;;)
	{
		// clean up upload tokens every 15 minutes
		time_t now = time(NULL);
		if(now >= last_clean + 60*15)
		{
			struct upload_entry *upload, *utmp;
			LIST_FOREACH_SAFE(upload, &upload_list, entries, utmp)
			{
				if(now > upload->expire)
				{
					LIST_REMOVE(upload, entries);
					os_unlink(upload->tmp_path);
					free(upload);
				}
			}
			
			last_clean = now;
		}
		
		
		struct repo_cmd_header hdr;
		if(socket_read_fully(mgr->socket, &hdr, sizeof(hdr)) != sizeof(hdr))
		{
			goto terminate;
		}
		
		if(hdr.magic != REPO_CMD_MAGIC)
		{
			goto terminate;
		}

		// access token must be NULL flushed
		if(hdr.access_token[sizeof(hdr.access_token) - 1] != 0)
		{
			goto terminate;
		}
		
		switch(hdr.type) {
			case REPO_CMD_AUTH:
				if(handle_cmd_auth(mgr, hdr.cookie, config) < 0) goto terminate;
				break;
			case REPO_CMD_CHECK_OID_EXIST:
			case REPO_CMD_GET_OID:
			case REPO_CMD_PUT_OID:
			{
				struct repo_oid_cmd_data data;
				if(socket_read_fully(mgr->socket, &data, sizeof(data)) != sizeof(data)) {
					goto terminate;
				}
				
				if(!git_lfs_verify_access_token(hdr.access_token, data.repo_id))
				{
					git_lfs_repo_send_error_response(mgr, hdr.cookie, "Invalid access token.");
					continue;
				}
				
				struct git_lfs_repo *repo = find_repo_by_id(config, data.repo_id);
				if(!repo) {
					git_lfs_repo_send_response(mgr, REPO_CMD_ERROR, hdr.cookie, NULL, 0, NULL);
					continue;
				}
			
				char path[PATH_MAX];
				char oid_str[65];
				oid_to_string(data.oid, oid_str);
				if(snprintf(path, sizeof(path), "%s/%.2s/%s", repo->root_dir, oid_str, oid_str + 2) >= sizeof(path)) {
					git_lfs_repo_send_error_response(mgr, hdr.cookie, "Unable to get object. Path is too long.");
					continue;
				}
				
				switch(hdr.type) {
					default: break;
					case REPO_CMD_CHECK_OID_EXIST:
						if(handle_cmd_check_oid(mgr, hdr.cookie, path) < 0) goto terminate;
						break;
					case REPO_CMD_GET_OID:
						if(handle_cmd_get_oid(mgr, hdr.cookie, path, oid_str) < 0) goto terminate;
						break;
					case REPO_CMD_PUT_OID:
						if(handle_cmd_put_oid(mgr, hdr.cookie, repo, data.oid, path) < 0) goto terminate;
						break;
					
				}
			}
				break;
			case REPO_CMD_COMMIT:
				if(handle_cmd_commit(mgr, hdr.access_token, hdr.cookie, config) < 0) goto terminate;
				break;
			case REPO_CMD_TERMINATE:
				git_lfs_repo_send_response(mgr, REPO_CMD_TERMINATE, hdr.cookie, NULL, 0, NULL);
				goto terminate;
				break;
			case REPO_CMD_CREATE_LOCK:
				if(handle_cmd_create_lock(mgr, hdr.access_token, hdr.cookie, config) < 0) goto terminate;
				break;
			case REPO_CMD_LIST_LOCKS:
				if(handle_list_locks(mgr, hdr.access_token, hdr.cookie, config) < 0) goto terminate;
				break;
			case REPO_CMD_DELETE_LOCK:
				if(handle_delete_lock(mgr, hdr.access_token, hdr.cookie, config) < 0) goto terminate;
				break;
			default:
				goto terminate;
		}
	}
	
terminate:;

	// clean up tmp files
	struct upload_entry *upload, *tmp;
	LIST_FOREACH_SAFE(upload, &upload_list, entries, tmp)
	{
		LIST_REMOVE(upload, entries);
		os_unlink(upload->tmp_path);
		free(upload);
	}
	
	
	return ret;
}

int git_lfs_repo_authenticate(struct repo_manager *mgr,
							  const struct git_lfs_config *config,
							  const struct git_lfs_repo *repo,
							  const char *username,
							  const char *password,
							  char *access_token,
							  size_t access_token_size,
							  time_t *expire,
							  char *error_msg,
							  size_t error_msg_buf_len)
{
	struct repo_cmd_auth_request request;
	struct repo_cmd_auth_response response;
	
	if(access_token_size < sizeof(response.access_token))
	{
		return -1;
	}

	memset(&request, 0, sizeof(request));
	request.repo_id = repo->id;
	if(strlcpy(request.username, username, sizeof(request.username)) >= sizeof(request.username))
	{
		return -1;
	}

	if(strlcpy(request.password, password, sizeof(request.password)) >= sizeof(request.password))
	{
		return -1;
	}
	
	if(git_lfs_repo_send_request(mgr,
								 REPO_CMD_AUTH,
								 "",
								 &request, sizeof(request),
								 &response, sizeof(response),
								 NULL,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	response.access_token[sizeof(response.access_token) - 1] = 0;
	strlcpy(access_token, response.access_token, sizeof(response.access_token));
	*expire = response.expire;

	return response.success;
}

int git_lfs_repo_check_oid_exist(struct repo_manager *mgr,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
								 unsigned char oid[32],
								 char *error_msg,
								 size_t error_msg_buf_len)
{
	struct repo_oid_cmd_data check_oid_req;

	check_oid_req.repo_id = repo->id;
	memcpy(check_oid_req.oid, oid, sizeof(check_oid_req.oid));

	struct repo_cmd_check_oid_response check_oid_resp;
	
	if(git_lfs_repo_send_request(mgr,
								 REPO_CMD_CHECK_OID_EXIST,
								 mgr->access_token,
								 &check_oid_req, sizeof(check_oid_req),
								 &check_oid_resp, sizeof(check_oid_resp),
								 NULL,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	return check_oid_resp.exist;
}

int git_lfs_repo_get_read_oid_fd(struct repo_manager *mgr,
								 const struct git_lfs_config *config,
								 const struct git_lfs_repo *repo,
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

	if(git_lfs_repo_send_request(mgr,
								 REPO_CMD_GET_OID,
								 mgr->access_token,
								 &request, sizeof(request),
								 &response, sizeof(response),
								 fd,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	*size = response.content_length;
	
	return 0;
}

int git_lfs_repo_get_write_oid_fd(struct repo_manager *mgr,
								  const struct git_lfs_config *config,
								  const struct git_lfs_repo *repo,
								  unsigned char oid[32],
								  int *fd,
								  uint32_t *ticket,
								  char *error_msg,
								  size_t error_msg_buf_len)
{
	struct repo_oid_cmd_data request;
	struct repo_cmd_put_oid_response response;
	
	request.repo_id = repo->id;
	memcpy(request.oid, oid, sizeof(request.oid));
	
	if(git_lfs_repo_send_request(mgr,
								 REPO_CMD_PUT_OID,
								 mgr->access_token,
								 &request, sizeof(request),
								 &response, sizeof(response),
								 fd,
								 error_msg, error_msg_buf_len) < 0) {
		return -1;
	}
	
	*ticket = response.ticket;

	return 0;
}

int git_lfs_repo_commit(struct repo_manager *mgr,
						uint32_t ticket,
						char *error_msg,
						size_t error_msg_buf_len)
{
	struct repo_cmd_commit_request request;
	memset(&request, 0, sizeof(request));
	request.ticket = ticket;
	
	return git_lfs_repo_send_request(mgr,
									 REPO_CMD_COMMIT,
									 mgr->access_token,
									 &request, sizeof(request),
									 NULL, 0,
									 NULL,
									 error_msg, error_msg_buf_len);
}

int git_lfs_repo_terminate_service(struct repo_manager *mgr)
{
	return git_lfs_repo_send_request(mgr, REPO_CMD_TERMINATE, "", NULL, 0, NULL, 0, NULL, NULL, 0);
}
