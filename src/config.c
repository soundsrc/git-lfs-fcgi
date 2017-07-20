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
#include "config.h"
#include <stdlib.h>
#include "compat/queue.h"

#include "lex.yy.c"
#include "y.tab.c"

int yyerror (const char *msg)
{
	printf("%s:%d: %s\n", parse_filename, scan_line_count, msg);
	return 0;
}

struct git_lfs_config *git_lfs_load_config(const char *path)
{
	yyin = fopen(path, "r");
	if(!yyin) {
		fprintf(stderr, "%s: Failed to open file.\n", path);
		return NULL;
	}
	
	struct git_lfs_config *config = (struct git_lfs_config *)calloc(1, sizeof(struct git_lfs_config));
	config->verify_upload = 1;
	config->port = 80;

	SLIST_INIT(&config->repos);

	scan_init();
	parse_init(path, config);

	yyparse();
	
	fclose(yyin);
	yyin = NULL;
	
	return config;
}

void git_lfs_free_config(struct git_lfs_config *config)
{
	free(config->base_url);
	free(config->socket);
	free(config->chroot_path);
	free(config->chroot_user);
	free(config->chroot_group);

	struct git_lfs_repo *repo, *temp;
	SLIST_FOREACH_SAFE(repo, &config->repos, entries, temp) {
		free(repo->name);
		free(repo->uri);
		free(repo->root_dir);
		
		SLIST_REMOVE(&config->repos, repo, git_lfs_repo, entries);
		free(repo);
	}

	free(config);
}
