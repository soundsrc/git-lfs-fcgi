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
#include "os/sandbox.h"
#include <unistd.h>
#include <sys/param.h>

int os_sandbox(enum sandbox_profile profile)
{
	switch(profile) {
		case SANDBOX_FILEIO:
			return pledge("stdio cpath rpath wpath flock sendfd recvfd", NULL);
		case SANDBOX_INET_SOCKET:
			return pledge("stdio inet sendfd recvfd", NULL);
		case SANDBOX_UNIX_SOCKET:
			return pledge("stdio unix sendfd recvfd", NULL);
		case SANDBOX_COMPUTE:
			return pledge("stdio", NULL);
	}

	return -1;
}
