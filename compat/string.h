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

#ifndef COMPAT_STRING_H
#define COMPAT_STRING_H

#include <stddef.h>
#include <string.h>

#if !defined(__FreeBSD__) && \
	!defined(__OpenBSD__) && \
	!defined(__APPLE__)

size_t strlcat(char *dst, const char *src, size_t dsize);
size_t strlcpy(char *dst, const char *src, size_t dsize);

#if !defined(__linux__)
char *strsep(char **stringp, const char *delim);
char *strndup(const char *str, size_t maxlen);
#endif

#endif

#if !defined(__OpenBSD__)
void explicit_bzero(void *buf, size_t len);
#endif

#endif
