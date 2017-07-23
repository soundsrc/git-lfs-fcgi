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
#include "os/socket.h"
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

int os_socketpair(int pair[2])
{
	return socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
}

int os_send_with_file_descriptor(int socket, const void *buffer, int size, int fd)
{
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	char buf[CMSG_SPACE(sizeof(fd))];

	struct iovec vec;
	vec.iov_base = (void *)buffer;
	vec.iov_len = size;
	
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	memmove(CMSG_DATA(cmsg), &fd, sizeof(fd));
	
	return sendmsg(socket, &msg, 0);
}

int os_recv_with_file_descriptor(int socket, void *buffer, int size, int *fd)
{
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	
	char buf[CMSG_SPACE(sizeof(fd))];
	
	struct iovec vec;
	vec.iov_base = buffer;
	vec.iov_len = size;
	
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	
	int ret = recvmsg(socket, &msg, 0);
	if(ret < 0) {
		return -1;
	}
	
	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	memmove(fd, CMSG_DATA(cmsg), sizeof *fd);
	
	return ret;
}

