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
#include <unistd.h>
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
