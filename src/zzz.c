/*
 * Copyright (c) 2015 Mark Heily <mark@heily.com>
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

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "zzz.h"
#include "log.h"

static int sockfd; /** Connection to zzzd */

static int send_credentials(int fd, int op, const char *msg, const size_t msglen);

int	zzz_init()
{
	const char *path = "/tmp/zzzd.sock"; /* XXX-for testing */
	struct sockaddr_un name;

	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, path, sizeof(name.sun_path));

	sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (!sockfd) return -1;

	if (connect(sockfd, (struct sockaddr *) &name, SUN_LEN(&name)) < 0) {
		return -1;
	}

	log_debug("connected to zzzd");

	return 0;
}

zzz_binding_t zzz_binding_alloc(const char *name)
{
	zzz_binding_t p;
	p = calloc(1, sizeof(*p));
	if (!p) return NULL;
	p->name = strdup(name);
	if (!p->name) { free(p); return NULL; }
	p->namelen = strlen(p->name);
	if (p->namelen > ZZZ_MAX_NAME_LEN) { free(p->name); free(p); return NULL; }
	p->namelen += 1;
	return (p);
}

void zzz_binding_free(zzz_binding_t binding)
{
	if (!binding) return;
	free(binding->name);
	free(binding->call_sig);
	free(binding->ret_sig);
	free(binding);
}

int zzz_bind(zzz_binding_t *binding, const char *name, mode_t mode, const char *call_sig, const char *ret_sig,
		void (*cb_func)(void *))
{
	zzz_binding_t b;

	b = zzz_binding_alloc(name);
	if (!b) {
		*binding = NULL;
		return -1;
	}
	b->permit_mode = mode;
	b->call_sig = strdup(call_sig);
	b->ret_sig = strdup(ret_sig);
	if (!b->call_sig || !b->ret_sig) {
		*binding = NULL;
		zzz_binding_free(b);
		return -1;
	}

	log_debug("sending packet");
	if (send_credentials(sockfd, 1234, b->name, b->namelen) < 0) {
		errx(1, "send_credentials");
	}
	log_debug("sent ok");
	return 0;
}

#ifdef __FreeBSD__
/* Borrowed code from FreeBSD:/usr/src/usr.sbin/nscd/nscdcli.c */
static int send_credentials(int fd, int op, const char *msg, const size_t msglen)
{
	int nevents;
	ssize_t result;
	int res;

	struct msghdr   cred_hdr;
	struct iovec    iov[2];

	struct {
			struct cmsghdr  hdr;
			struct cmsgcred creds;
	} cmsg;

	memset(&cmsg, 0, sizeof(cmsg));
	cmsg.hdr.cmsg_len = sizeof(cmsg);
	cmsg.hdr.cmsg_level = SOL_SOCKET;
	cmsg.hdr.cmsg_type = SCM_CREDS;

	memset(&cred_hdr, 0, sizeof(struct msghdr));
	cred_hdr.msg_iov = &iov;
	cred_hdr.msg_iovlen = 2;
	cred_hdr.msg_control = &cmsg;
	cred_hdr.msg_controllen = sizeof(cmsg);

	iov[0].iov_base = &op;
	iov[0].iov_len = sizeof(op);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;
	log_debug("msg=%s len=%zu", msg, msglen);
	result = (sendmsg(fd, &cred_hdr, 0) == -1) ? -1 : 0;
	return (result);
}
#endif

int	zzz_connect(zzz_connection_t conn)
{
	const char *path = "/tmp/zzzd.sock"; /* XXX-for testing */
	struct sockaddr_un name;

	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, path, sizeof(name.sun_path));

	sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (!sockfd) err(1, "socket");

	if (connect(sockfd, (struct sockaddr *) &name, SUN_LEN(&name)) < 0)
			err(1, "connect");

	log_info("connection established");

#ifdef __linux__
	int i = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &i, sizeof(i)) < 0)
		err(1, "setsockopt");
#error TODO actually write send_credentials()
#elif defined(__FreeBSD__)
	if (send_credentials(sockfd, ZZZ_CONNECT_OP, conn->name, conn->namelen) < 0) {
		errx(1, "send_credentials");
	}
#else
#error Unsupported credentials passing mechanism
#endif

	///log_info("---CREDENTIAL STUFF IS DONE---");
	///if (send(sockfd, conn->name, conn->namelen, 0) < 0) err(1, "send");
	///log_info("sent data");

	//int32_t response;
	//if (recv(sockfd, &response, sizeof(response), 0) < 0) err(1, "recv");
	//log_info("got response: %d");
	return 0;
}

zzz_connection_t
zzz_connection_alloc(const char *name)
{
	struct sockaddr_un saun;
	zzz_connection_t p;

	p = calloc(1, sizeof(p));
	if (!p) return NULL;
	p->name = strdup(name);
	if (!p->name) { free(p); return NULL; }
	p->namelen = strlen(p->name);
	if (p->namelen > ZZZ_MAX_NAME_LEN) errx(1, "name too long");
	p->namelen += 1;
	saun.sun_family = AF_LOCAL;
	p->sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (!p->sockfd) { err(1, "socket");
	//TODO: would prefer to: free(p->name); free(p); return NULL;
	}
	return (p);
}

void
zzz_connection_free(zzz_connection_t conn)
{
	if (!conn) return;
	free(conn->name);
	free(conn);
}
