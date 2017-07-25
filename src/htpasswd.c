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
#include "htpasswd.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "compat/string.h"
#include "crypt_blowfish.h"

struct htpasswd *load_htpasswd_file(const char *filename)
{
	char line[128];

	FILE *fp = fopen(filename, "r");
	if(!fp) return NULL;
	
	struct htpasswd *htp = calloc(1, sizeof *htp);
	while(fgets(line, sizeof(line), fp))
	{
		line[sizeof(line) - 1] = 0;
		
		char *start = line;
		if(!*start) continue;

		// trim string
		while(isspace(*start))
		{
			++start;
		}

		char *end = start + strlen(line);
		while(end > start && isspace(*(end - 1)))
		{
			*--end = 0;
		}
		
		if(start == end) continue; // empty

		char *username = strsep(&start, ":");
		if(!username)
		{
			continue;
		}

		char *bcrypt_hash = strsep(&start, " \r\n");
		if(!bcrypt_hash)
		{
			continue;
		}
		
		if(60 != strnlen(bcrypt_hash, 61) ||
		   bcrypt_hash[0] != '$' ||
		   bcrypt_hash[1] != '2' ||
		   (bcrypt_hash[2] != 'a' && bcrypt_hash[2] != 'y') ||
		   bcrypt_hash[3] != '$' ||
		   bcrypt_hash[4] < '0' || bcrypt_hash[4] > '9' ||
		   bcrypt_hash[5] < '0' || bcrypt_hash[5] > '9' ||
		   bcrypt_hash[6] != '$')
		{
			fprintf(stderr, "htpasswd: Ignored user '%s', invalid bycrypt hash. Use 'htpasswd -B' option for bcrypt passwords.\n", username);
			continue;
		}
		unsigned int count = (bcrypt_hash[4] - '0') * 10 + (bcrypt_hash[5] - '0');
		if(count < 4 || count > 17)
		{
			fprintf(stderr, "htpasswd: Ignored user '%s', invalid bcrypt count.\n", username);
			continue;
		}

		struct password_entry *user = calloc(1, sizeof *user);
		if(strlcpy(user->username, username, sizeof(user->username)) >= sizeof(user->username))
		{
			fprintf(stderr, "htpasswd: Ignored user '%s', username is too long.\n", username);
			free(user);
			continue;
		}

		if(strlcpy(user->bcrypt_hash, bcrypt_hash, sizeof(user->bcrypt_hash)) >= sizeof(user->bcrypt_hash))
		{
			fprintf(stderr, "htpasswd: Ignored user '%s', hash is too long.\n", username);
			free(user);
			continue;
		}
		
		SLIST_INSERT_HEAD(htp, user, entries);
	}

	fclose(fp);
	
	return htp;
}

int authenticate_user_with_password(struct htpasswd *htpasswd, const char *username, const char *password)
{
	struct password_entry *user;
	SLIST_FOREACH(user, htpasswd, entries)
	{
		if(0 == strcmp(user->username, username))
		{
			char hash[61];

			if (_crypt_blowfish_rn(password, user->bcrypt_hash, hash, sizeof(hash)) == NULL)
			{
				return 0;
			}
			
			if(0 == strncmp(user->bcrypt_hash, hash, 31))
			{
				return 1;
			}
		}
	}
	
	return 0;
}

void free_htpasswd(struct htpasswd * htpasswd)
{
	struct password_entry *user;
	while (!SLIST_EMPTY(htpasswd))
	{
		user = SLIST_FIRST(htpasswd);
		SLIST_REMOVE_HEAD(htpasswd, entries);
		free(user);
	}
	free(htpasswd);
}
