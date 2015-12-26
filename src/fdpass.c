/*
 * Copyright (c) 2015 Mark Heily <mark@heily.com>
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/uio.h>
#include <syslog.h>

#include <errno.h>
#include <err.h>
#include <string.h>

#include "fdpass.h"
#include "log.h"

/* Temporary hack for FreeBSD compilation */
#define HAVE_SENDMSG 1
#define HAVE_RECVMSG 1
#define HAVE_CONTROL_IN_MSGHDR 1

int
fdpass_send(int socket, int fd, void *base, size_t len)
{
#if defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
#endif

	if (base == NULL) {
		vec.iov_base = &ch;
		vec.iov_len = 1;
	} else {
		vec.iov_base = base;
		vec.iov_len = len;
	}
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(socket, &msg, 0)) == -1) {
		if (errno == EAGAIN)
			return (-1);
		log_errno("sendmsg(2)");
		return -1;
	}
	if (n == 0)
	{
		log_error("sendmsg: expected setn >0 got %ld", (long)n);
		return -1;
	}
#else
#error Unsupported OS
#endif

	return (0);
}

int
fdpass_recv(int socket, void *base, socklen_t *len)
{
#if defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	ssize_t n;
	int fd;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
	if (base == NULL) {
		log_error("usage error");
		return -1;
	}
	vec.iov_base = base;
	vec.iov_len = *len;

	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);
#endif

	while ((n = recvmsg(socket, &msg, 0)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return (-1);
		log_errno("recvmsg(2)");
		return -1;
	}
	if (n == 0)
	{
		log_error("recvmsg: expected received >0 got %ld", (long)n);
		return -1;
	}
	if (len != 0)
		*len = n;

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	if (msg.msg_accrightslen != sizeof(fd))
	{
		log_error("no fd");
		return -1;
	}
#else
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg)
	{
		log_error("no cmsg");
		return -1;
	}
	if (cmsg->cmsg_type != SCM_RIGHTS)
	{
		log_error("expected type %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		return -1;
	}
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
#endif
		
	return fd;
#else
#error Unsupported OS
#endif
}
