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
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../include/ipc.h"
#include "ipc_private.h"
#include "fdpass.h"
#include "log.h"

static int kqfd;
static const char *statedir = "/tmp/zzz";
static const char *sockpath = "/tmp/zzz/zzzd.sock";
static int sockfd;

static void setup_directories();
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

static int
read_request(ipc_operation_t *iop, int fd)
{
	ssize_t bytes;

	bytes = read(fd, iop, sizeof(*iop));
	if (bytes < 0) {
		log_errno("read(2)");
		return -1;
	}
	if (bytes < sizeof(*iop)) {
		log_error("short read; expected %zu but got %zu", sizeof(*iop), (size_t) bytes);
		return -1;
	}

	if (ipc_getpeereid(fd, &iop->uid, &iop->gid) < 0) {
		log_errno("getpeereid(2)");
		return -1;
	}

	return 0;
}

/* DO NOT EDIT: this has been moved to ipc.c */
static int 
bind_to_name(const char *name)
{
	struct sockaddr_un sock;
	int fd = -1;
	int len;

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/services/%s", statedir, name);
	if (len >= sizeof(sock.sun_path) || len < 0) {
		log_error("buffer allocation error");
		return -1;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_errno("socket(2)");
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		log_errno("bind(2)");
		close(fd);
		return -1;
	}

	log_debug("service name `%s' bound to server fd %d", name, fd);

	return fd;
}

static int
bind_request_handler(ipc_operation_t iop, int client_fd)
{
	int service_fd;
	char c = '\0';

	service_fd = bind_to_name(iop.name);
	if (service_fd < 0) {
		log_error("unable to bind to name: %s", iop.name);
		return -1;
	}

	if (fdpass_send(client_fd, service_fd, &c, 1) < 0) {
		log_error("unable to pass the service descriptor");
		close(service_fd);
		return -1;
	}

	close(service_fd);
	return 0;
}

static void 
connection_handler()
{
	int client_fd;
	ipc_operation_t iop;
	struct sockaddr sa;
	socklen_t sa_len;

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
			"accepted connection on fd %d from uid %d gid %d; request: op=%s(%d) name=%s",
			client_fd, iop.uid, iop.gid, opcode_to_str(iop.opcode),
			iop.opcode, iop.name);

	switch (iop.opcode) {
	case IPC_OP_BIND:
		if (bind_request_handler(iop, client_fd) < 0) {
			log_error("bind request failed");
			goto err_out;
		}
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
	char path[PATH_MAX];
	struct kevent kev;
	int len;

	len = snprintf(path, sizeof(path), "%s/zzzd.sock", statedir);
	if (len >= sizeof(path) || len < 0) {
		log_error("buffer allocation error");
		abort();
	}

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

static void
setup_directories()
{
	char path[PATH_MAX];
	int len;

	if (access(statedir, X_OK) < 0) {
		log_errno("access(2) of %s", statedir);
		abort();
	}

	len = snprintf(path, sizeof(path), "%s/services", statedir);
	if (len >= sizeof(path) || len < 0) {
		log_error("buffer allocation error");
		abort();
	}

	if (access(path, X_OK) < 0) {
		if (errno == ENOENT) {
			if (mkdir(path, 0755) < 0) {
				log_errno("mkdir(2) of %s", path);
				abort();
			}
		} else {
			log_errno("access(2) of %s", path);
			abort();
		}
	}
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

	setup_directories();
	setup_socket();
	setup_signal_handlers();
	main_loop();
	exit(EXIT_SUCCESS);
}
