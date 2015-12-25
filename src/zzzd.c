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

#include <sys/types.h>

#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "zzz.h"
#include "fdpass.h"
#include "log.h"

static int kqfd;
static const char *sockpath = "/tmp/zzzd.sock"; /* XXX-for testing */
static int sockfd;

/* KLUDGE: not sure why this isn't visible */
int getpeereid(int, uid_t *, gid_t *);

struct binding {
	SLIST_ENTRY(binding) sle;
	char *name;
	int  fd; /** The server program */
};

static SLIST_HEAD(, binding) bindlist = SLIST_HEAD_INITIALIZER(bindlist);

static void connection_handler();

static void
signal_handler(int signum)
{
	(void) signum;
}

static void
setup_signal_handlers()
{
	const int signals[] = { SIGHUP, SIGUSR1, SIGCHLD, SIGINT, SIGTERM, 0 };
	int i;
	struct kevent kev;

	for (i = 0; signals[i] != 0; i++) {
		EV_SET(&kev, signals[i], EVFILT_SIGNAL, EV_ADD, 0, 0,
				&setup_signal_handlers);
		if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
			abort();
		if (signal(signals[i], signal_handler) == SIG_ERR)
			abort();
	}
}

static void
main_loop()
{
	struct kevent kev;

	log_debug("main loop");
	for (;;) {
		if (kevent(kqfd, NULL, 0, &kev, 1, NULL) < 1) {
			if (errno == EINTR) {
				continue;
			} else {
				log_errno("kevent");
				abort();
			}
		}
		if (kev.udata == &setup_signal_handlers) {
			switch (kev.ident) {
			case SIGHUP:
				break;
			case SIGUSR1:
				break;
			case SIGCHLD:
				break;
			case SIGINT:
			case SIGTERM:
				log_notice("caught signal %lu, exiting", kev.ident);
				//do_shutdown();
				exit(0);
				break;
			default:
				log_error("caught unexpected signal");
			}
		} else if (kev.udata == &connection_handler) {
			connection_handler();
		} else {
			log_warning("spurious wakeup, no known handlers");
		}
	}
}

const char *opcode_to_str(int opcode)
{
	switch (opcode) {
	case ZZZ_BIND_OP:
		return "bind";
	case ZZZ_CONNECT_OP:
		return "connect";
	default:
		return "invalid-opcode";
	}
}

static int
read_request(zzz_ipc_operation_t *iop, int fd)
{
	socklen_t len;
	fdpass_cred_t cred;

	if (getpeereid(fd, &iop->uid, &iop->gid) < 0) {
		log_errno("getpeereid(2)");
		return -1;
	}

	if (read(fd, iop, sizeof(*iop)) < sizeof(*iop)) {
		log_errno("read(2)");
		return -1;
	}

	iop->pid = 0;

	return 0;
}

static int 
bind_to_name(const char *name, size_t namelen, int fd)
{
	struct binding *b;

	b = malloc(sizeof(*b));
	if (b)
		b->name = strdup(name);
	if (!b || !b->name) {
		log_errno("malloc");
		return -1;
	}
	b->fd = fd;
	SLIST_INSERT_HEAD(&bindlist, b, sle);
	log_debug("service name `%s' bound to server fd %d", name, fd);
	return 0;
}

static struct binding * 
lookup_name(const char *name)
{
	struct binding *b;

	SLIST_FOREACH(b, &bindlist, sle) {
		if (strcmp(b->name, name) == 0)
			return b;
	}

	return NULL;
}

static int
connect_to_name(zzz_ipc_operation_t *iop)
{
	struct binding *bn;

	bn = lookup_name(iop->name);
	if (bn == NULL) {
		log_error("name not found");
		return -1;
	}
	log_debug("sending client fd %d to server fd %d", iop->client_fd, bn->fd);
	if (fdpass_send(bn->fd, iop->client_fd, iop, sizeof(*iop)) < 0) {
		log_error("name not found");
		return -1;
	}
	log_debug("client connected to server");
	return 0;
}

static void 
connection_handler()
{
	int client_fd;
	zzz_ipc_operation_t iop;
	struct sockaddr sa;
	socklen_t sa_len;
	char buf[ZZZ_MAX_NAME_LEN];
	ssize_t len;

	log_debug("incoming connection on fd %d", sockfd);

	client_fd = accept(sockfd, &sa, &sa_len);
	if (client_fd < 0) {
		log_errno("accept(2)");
		goto err_out;
	}

	if (read_request(&iop, client_fd) < 0) {
		log_error("failed to read request");
		goto err_out;
	}

	log_info(
			"accepted connection on fd %d from uid %d gid %d pid %d; request: op=%s(%d) name=%s",
			client_fd, iop.uid, iop.gid, iop.pid, opcode_to_str(iop.opcode),
			iop.opcode, iop.name);

	switch (iop.opcode) {
	case ZZZ_BIND_OP:
		if (bind_to_name(iop.name, iop.namelen, client_fd) < 0)
			goto err_out;
		break;

	case ZZZ_CONNECT_OP:
		iop.client_fd = client_fd;
		log_debug("connecting..");
		if (connect_to_name(&iop) < 0)
			goto err_out;
		log_debug("done..");
		break;

	default:
		log_error("invalid opcode %d", iop.opcode);
		goto err_out;
	}

	return;

err_out:
	log_error("aborting connection");
	if (client_fd >= 0) close(client_fd);
		return;
}

void cleanup_socket()
{
	if (unlink(sockpath) < 0)
		log_errno("unlink");
}

void setup_socket()
{
	struct kevent kev;

	const char *path = "/tmp/zzzd.sock"; /* XXX-for testing */
	struct sockaddr_un name;

	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, path, sizeof(name.sun_path));

	sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (!sockfd)
		err(1, "socket");

	if (bind(sockfd, (struct sockaddr *) &name, SUN_LEN(&name)) < 0)
		err(1, "bind");

	if (listen(sockfd, 1024) < 0)
		err(1, "listen");

	atexit(cleanup_socket);

	EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
			&connection_handler);
	if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
		abort();
}

int main(int argc, char *argv[])
{
	if (0 && daemon(0, 0) < 0) {
		fprintf(stderr, "Unable to daemonize");
		exit(EX_OSERR);
		log_open("zzzd", "/tmp/zzzd.log"); /* XXX insecure, for testing only */
	} else {
		log_open("zzzd", "/dev/stderr");
	}

	if ((kqfd = kqueue()) < 0)
		abort();

	setup_socket();
	setup_signal_handlers();
	main_loop();
	exit(EXIT_SUCCESS);
}
