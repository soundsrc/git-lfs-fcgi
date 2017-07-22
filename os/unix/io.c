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
#include "io.h"
#include <unistd.h>
#include <fcntl.h>

int os_open_read(const char *filename)
{
	return open(filename, O_RDONLY);
}

int os_open_create(const char *filename, int mode)
{
	return open(filename, O_CREAT | O_WRONLY, mode);
}

int os_read(int fd, void *buffer, int size)
{
	return read(fd, buffer, size);
}

int os_write(int fd, const void *buffer, int size)
{
	return write(fd, buffer, size);
}

int os_close(int fd)
{
	return close(fd);
}
