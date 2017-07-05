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

#include "mkdir_recusive.h"
#include <string.h>
#include <stdlib.h>
#include "compat/string.h"
#include "os/filesystem.h"

int mkdir_recursive(const char *path, int mode)
{
	char *path_copy;
	char *path_next;
	int err = 0;
	
	size_t path_len = strlen(path);
	path_copy = malloc(path_len + 1);
	if(strlcpy(path_copy, path, path_len + 1) >= path_len + 1) {
		// this should never happen
		err = -1;
		goto fail;
	}
	
	path_next = path_copy;
	if(*path_next == '/') path_next++;

	while((path_next = strchr(path_next, '/'))) {
		char save_chr = *path_next; // save the next path char
		*path_next = 0; // terminate
		
		if(!os_is_directory(path_copy)) {
			err = os_mkdir(path_copy, mode);
			if(err != 0) goto fail;
		}
		
		*path_next = save_chr;
		path_next++;
	}
	
	if(!os_is_directory(path_copy)) {
		err = os_mkdir(path_copy, mode);
		if(err != 0) goto fail;
	}
	
fail:
	free(path_copy);
	
	return err;
}
