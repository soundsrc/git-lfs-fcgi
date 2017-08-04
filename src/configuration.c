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
#include "configuration.h"
#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"
#include "compat/string.h"
#include "compat/queue.h"

extern int yyparse (void);

struct git_lfs_config *git_lfs_load_config(const char *path)
{
	struct git_lfs_config *config = (struct git_lfs_config *)calloc(1, sizeof(struct git_lfs_config));
	config->verify_upload = 1;
	config->port = 80;

	SLIST_INIT(&config->repos);

	if(!config_scan_init(path))
	{
		goto error;
	}
	config_parse_init(config);

	if(yyparse() != 0)
	{
		goto error;
	}
	
	if(!config->user)
	{
		config->user = strdup("git-lfs");
	}
	
	if(!config->group)
	{
		config->group = strdup("git-lfs");
	}
	
	if(!config->process_chroot)
	{
		config->process_chroot = strdup("/var/lib/git-lfs-server/empty");
	}

	return config;
error:
	git_lfs_free_config(config);
	return NULL;
}

void git_lfs_free_config(struct git_lfs_config *config)
{
	free(config->base_url);
	free(config->fastcgi_socket);
	free(config->chroot_path);
	free(config->user);
	free(config->group);
	free(config->process_chroot);

	while (!SLIST_EMPTY(&config->repos))
	{
		struct git_lfs_repo *repo = SLIST_FIRST(&config->repos);
		SLIST_REMOVE_HEAD(&config->repos, entries);
		
		sqlite3_close(repo->locks_db);
		free(repo->auth_realm);
		free(repo->auth);
		free(repo->name);
		free(repo->uri);
		free(repo->root_dir);
		
		free(repo);
	}

	free(config);
}
