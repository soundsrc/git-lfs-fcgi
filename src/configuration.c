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
#include <string.h>
#include "compat/string.h"
#include "compat/queue.h"

extern int yyparse (void);

struct git_lfs_config *git_lfs_load_config(const char *path)
{
	struct git_lfs_config *config = (struct git_lfs_config *)calloc(1, sizeof(struct git_lfs_config));
	if(!config) return NULL;

	config->fastcgi_server = 1;
	config->port = 80;
	config->num_threads = 2;

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
		config->process_chroot = strdup("/var/lib/git-lfs-fcgi/run");
	}

	size_t chroot_path_len = 0;
	if(config->chroot_path)
	{
		chroot_path_len = strlen(config->chroot_path);
	}

	struct git_lfs_repo *repo;
	SLIST_FOREACH(repo, &config->repos, entries)
	{
		if(chroot_path_len)
		{
			if(0 != strncmp(config->chroot_path, repo->full_root_dir, chroot_path_len) ||
			   repo->full_root_dir[chroot_path_len] != '/')
			{
				fprintf(stderr, "error: The repo '%s' root_dir (%s) must start with the chroot_path (%s).\n", repo->name, repo->full_root_dir, config->chroot_path);
				goto error;
			}
			
			repo->root_dir = strdup(repo->full_root_dir + chroot_path_len);
		}
		else
		{
			repo->root_dir = strdup(repo->full_root_dir);
		}
	}
	
	if(!config->fastcgi_socket)
	{
		config->fastcgi_socket = strdup("/var/lib/git-lfs-fcgi/run/git-lfs-fcgi.sock");
	}
	
	if(config->fastcgi_server && config->fastcgi_socket[0] != ':')
	{
		size_t process_chroot_path_len = strlen(config->process_chroot);
		if(0 != strncmp(config->fastcgi_socket, config->process_chroot, process_chroot_path_len) ||
		   config->fastcgi_socket[process_chroot_path_len] != '/')
		{
			fprintf(stderr, "FastCGI socket path (%s) must start with '%s'.\n", config->fastcgi_socket, config->process_chroot);
			goto error;
		}
		
		char *chroot_fastcgi_socket = strdup(config->fastcgi_socket + process_chroot_path_len);
		free(config->fastcgi_socket);
		config->fastcgi_socket = chroot_fastcgi_socket;
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

		free(repo->auth_realm);
		free(repo->auth);
		free(repo->name);
		free(repo->uri);
		free(repo->root_dir);
		free(repo->full_root_dir);
		
		free(repo);
	}

	free(config);
}
