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

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdint.h>
#include "compat/queue.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

struct htpasswd;
struct git_lfs_repo
{
	SLIST_ENTRY(git_lfs_repo) entries;

	uint32_t id; // unique repo id
	char *name; // name of repo
	char *uri; // uri
	char *full_root_dir; // full path to the root_dir
	char *root_dir; // root directory for files, relative to chroot_path
	
	int enable_authentication;
	char *auth_realm;
	struct htpasswd *auth;
};

SLIST_HEAD(git_lfs_repo_list, git_lfs_repo);

struct git_lfs_config
{
	int verbose;
	int verify_upload;
	
	int port; // listening port
	
	char *base_url; // eg. http://example.com
	
	int fastcgi_server; // enable fastcgi server
	char *fastcgi_socket; // socket path or :port for fastcgi

	int num_threads;
	
	char *chroot_path;
	char *user;
	char *group;
	
	char *process_chroot;

	struct git_lfs_repo_list repos;
};

struct git_lfs_config *git_lfs_load_config(const char *path);
void git_lfs_free_config(struct git_lfs_config *config);

extern int config_scan_init(const char *filename);
int config_parse_init(struct git_lfs_config *config);

#endif
