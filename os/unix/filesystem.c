/*
 * Copyright (c) 2016 Sound <sound@sagaforce.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <glob.h>
#include <sys/stat.h>
#include "os/filesystem.h"

int os_is_directory(const char *path)
{
	struct stat st;
	int err = stat(path, &st);
	if(err != 0) return 0;
	
	return S_ISDIR(st.st_mode);
}

int os_file_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

long os_file_size(const char *path)
{
	struct stat st;
	int err = stat(path, &st);
	if(err != 0) return 0;
	
	return st.st_size;
}

int os_mkdir(const char *path, int mode)
{
	return mkdir(path, mode);
}

int os_rename(const char *src_path, const char *dest_path)
{
	return rename(src_path, dest_path);
}

int os_unlink(const char *path)
{
	return unlink(path);
}

int os_chroot(const char *path)
{
	if(chdir(path) < 0)
	{
		return -1;
	}

	return chroot(path);
}

int os_mkstemp(char *template_path)
{
	return mkstemp(template_path);
}

int os_umask(int mode)
{
	return umask(mode);
}

const char ** os_glob(const char *pattern, int *num_matches)
{
	glob_t glob_results;
	if(glob(pattern, GLOB_NOCHECK, NULL, &glob_results) < 0)
	{
		return NULL;
	}
	
	size_t pointers_size = glob_results.gl_pathc * sizeof(const char *);
	size_t alloc_size = pointers_size;

	// determine the amount of memory to allocate
	for (int i = 0; i < glob_results.gl_pathc; ++i)
	{
		const char *filename = glob_results.gl_pathv[i];
		size_t len = strlen(filename) + 1;
		len = (len + 3) & ~3; // align-4
		alloc_size += len;
	}
	
	const char **result = calloc(1, alloc_size);
	char *filenames_start = (char *)result + pointers_size;
	
	for (int i = 0; i < glob_results.gl_pathc; ++i)
	{
		size_t n = strlen(glob_results.gl_pathv[i]) + 1;
		strncpy(filenames_start, glob_results.gl_pathv[i], n);
		filenames_start[n - 1] = 0;
		result[i] = filenames_start;
		filenames_start += (n + 3) & ~3;
	}
	
	if(num_matches) *num_matches = glob_results.gl_pathc;

	assert((char *)result + alloc_size == filenames_start);
	
	return result;
}
