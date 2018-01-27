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
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "os/droproot.h"

int os_droproot(const char *chroot_path, const char *user, const char *group)
{
	uid_t uid;
	gid_t gid;

	struct passwd *pwd = getpwnam(user);
	if(!pwd) {
		fprintf(stderr, "Failed to resolve user '%s'. User does not exist?\n", user);
		return -1;
	}
	uid = pwd->pw_uid;
	
	struct group *grp = getgrnam(group);
	if(!grp) {
		fprintf(stderr, "Failed to resolve group '%s'. Group does not exist?\n", group);
		return -1;
	}
	gid = grp->gr_gid;

	if(chroot_path)
	{
		if(chdir(chroot_path) < 0) {
			fprintf(stderr, "Failed to chroot to directory '%s'.\n", chroot_path);
			return -1;
		}
		
		if(chroot(chroot_path) < 0) {
			fprintf(stderr, "Failed to chroot to directory '%s'.\n", chroot_path);
			return -1;
		}
	}

	if(setgid(gid) < 0) {
		fprintf(stderr, "Failed to change to group '%s'.\n", group);
		return -1;
	}
	
	if(setuid(uid) < 0) {
		fprintf(stderr, "Failed to change to user '%s'.\n", user);
		return -1;
	}
	
	return 0;
}
