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

struct git_lfs_config;

enum repo_cmd_type
{
	CHECK_OID_EXIST,
	GET_OID,
	PUT_OID,
	TERMINATE
};

struct repo_cmd_base
{
	uint32_t cookie;
	enum repo_cmd_type type;
};

struct repo_check_oid_cmd
{
	uint8_t oid[32];
};

struct repo_check_oid_reponse
{
	int exist;
};

int git_lfs_repo_manager_service(int socket);

int git_lfs_repo_check_oid_exist(const struct git_lfs_config *config, const char *repo, const char *auth, unsigned char oid[32]);
int git_lfs_repo_get_read_oid_fd(const struct git_lfs_config *config, const char *repo, const char *auth, unsigned char oid[32]);
int git_lfs_repo_get_write_oid_fd(const struct git_lfs_config *config, const char *repo, const char *auth, unsigned char oid[32]);
int git_lfs_repo_terminate_service();

#endif /* repo_manager_h */
