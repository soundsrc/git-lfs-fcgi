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
#include <signal.h>
#include <ctype.h>
#include <getopt.h>
#include "compat/string.h"
#include "os/filesystem.h"
#include "os/mutex.h"
#include "os/threads.h"
#include "os/droproot.h"
#include "os/io.h"
#include "os/socket.h"
#include "os/process.h"
#include "os/sandbox.h"
#include "config.h"
#include "socket_io.h"
#include "httpd.h"
#include "git_lfs_server.h"
#include "repo_manager.h"
#include "mongoose.h"

int main(int argc, char *argv[])
{
	int verbose = 0;
	char config_path[4096] = "/etc/git-lfs-server/git-lfs.conf";

	static struct option long_options[] =
	{
		{ "help", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 'v' },
		{ "config", required_argument, 0, 'f' },
		{ 0, 0, 0, 0 }
	};
	
	int opt_index;
	int c;
	while((c = getopt_long (argc, argv, "vf:", long_options, &opt_index)) >= 0)
	{
		switch(c) {
			case 'v':
				verbose++;
				break;
			case 'f':
				if(strlcpy(config_path, optarg, sizeof(config_path)) >= sizeof(config_path))
				{
					fprintf(stderr, "Invalid config path. Too long.\n");
					return -1;
				}
				break;
		}
	}
	
	struct git_lfs_config *config = git_lfs_load_config(config_path);
	if(!config) {
		fprintf(stderr, "Unable to load config.\n");
		goto error0;
	}
	config->verbose = verbose;

	
	if(config->chroot_path)
	{
		if(!config->chroot_user || !config->chroot_group)
		{
			fprintf(stderr, "chroot_user and chroot_group must be specified when using chroot_path.\n");
			goto error1;
		}
		
		if(os_droproot(config->chroot_path, config->chroot_user, config->chroot_group) < 0)
		{
			fprintf(stderr, "Failed to chroot and set user/group name.\n");
			goto error1;
		}
	}

	if(verbose) {
		if(config->fastcgi_server) {
			printf("FastCGI enabled.\n");
			printf("Socket Path: %s\n", config->fastcgi_socket);
		}
		if(config->chroot_path) {
			printf("Chroot: %s\n", config->chroot_path);
			printf("User: %s\n", config->chroot_user);
			printf("Group: %s\n", config->chroot_group);
		}
	}
	
	int fd[2];
	if(os_socketpair(fd) < 0) {
		fprintf(stderr, "Failed to create sockets.\n");
		goto error1;
	}
	
	int pid = os_fork();
	if(pid < 0) {
		fprintf(stderr, "Failed to fork process.\n");
		os_close(fd[1]);
		os_close(fd[0]);
		goto error1;
	}
	
	if(pid == 0) {
		if(os_sandbox(SANDBOX_FILEIO) < 0) {
			fprintf(stderr, "Sandbox failed.\n");
			goto error1;
		}

		os_close(fd[0]);
		git_lfs_repo_manager_service(fd[1]);
		os_close(fd[1]);
	} else {
		
		// todo, allow configurable
		if(os_chroot("/var/empty") < 0) {
			fprintf(stderr, "warning: Chroot failed.\n");
		}

		// only allow internet
		if(os_sandbox(SANDBOX_INET_SOCKET) < 0) {
			fprintf(stderr, "Sandbox failed.\n");
			goto error1;
		}

		os_close(fd[1]);
		git_lfs_start_httpd(config);
		os_close(fd[0]);
	}
error1:
	git_lfs_free_config(config);
error0:
	return 0;
}
