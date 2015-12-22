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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "zzz.h"
#include "log.h"

static int kqfd;
static const char *sockpath = "/tmp/zzzd.sock"; /* XXX-for testing */
static int sockfd;

struct ipc_operation {
	int opcode;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	char name[ZZZ_MAX_NAME_LEN];
};
static void connection_handler();

static void signal_handler(int signum) {
	(void) signum;
}

static void setup_signal_handlers()
{
	const int signals[] = {SIGHUP, SIGUSR1, SIGCHLD, SIGINT, SIGTERM, 0};
	int i;
    struct kevent kev;

    for (i = 0; signals[i] != 0; i++) {
        EV_SET(&kev, signals[i], EVFILT_SIGNAL, EV_ADD, 0, 0, &setup_signal_handlers);
        if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0) abort();
        if (signal(signals[i], signal_handler) == SIG_ERR) abort();
    }
}

static void main_loop() {
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

#ifdef __FreeBSD__
/* Based on FreeBSD's /usr/src/usr.sbin/nscd/query.c **/
static int get_peer_creds(struct ipc_operation *result) {
    struct msghdr   cred_hdr;
    struct iovec    iov[2];
    struct cmsgcred *cred;

    struct {
            struct cmsghdr  hdr;
            char cred[CMSG_SPACE(sizeof(struct cmsgcred))];
    } cmsg;

    memset(&cred_hdr, 0, sizeof(struct msghdr));
    cred_hdr.msg_iov = &iov;
    cred_hdr.msg_iovlen = 2;
    cred_hdr.msg_control = (caddr_t)&cmsg;
    cred_hdr.msg_controllen = CMSG_LEN(sizeof(struct cmsgcred));

    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = &result->opcode;
    iov[0].iov_len = sizeof(result->opcode);
    iov[1].iov_base = &result->name;
    iov[1].iov_len = sizeof(result->name) -1;

    if (recvmsg(sockfd, &cred_hdr, 0) == -1) {
    	log_errno("recvmsg");
    	return -1;
    }

    if (cmsg.hdr.cmsg_len < CMSG_LEN(sizeof(struct cmsgcred))
            || cmsg.hdr.cmsg_level != SOL_SOCKET
            || cmsg.hdr.cmsg_type != SCM_CREDS) {
            log_error("bad response");
            return -1;
    }

    cred = (struct cmsgcred *)CMSG_DATA(&cmsg);
    result->uid = cred->cmcred_uid;
    result->gid = cred->cmcred_gid;
    result->pid = cred->cmcred_pid;
    /* TODO: copy out the supplemental groups */

    return 0;
}
#endif

static void connection_handler()
{
	struct ipc_operation iop;
    char buf[ZZZ_MAX_NAME_LEN];
	ssize_t len;

	if (get_peer_creds(&iop) < 0) return;
	log_info("connection from uid %d gid %d pid %d; op=%d name=%s",
			iop.uid, iop.gid, iop.pid, iop.opcode, iop.name);
	//len = recv(sockfd, &buf, sizeof(buf), 0);
	//if (len < 0) err(1, "recv");
	//log_info("got %zu bytes", (unsigned long) len);
	//log_info("message: %s", (char *) &buf);
    //log_error("TODO");

    //uint32_t response = -1;
    //if (send(sockfd, &response, sizeof(response), 0) < 0) err(1, "send");
    //log_info("sent response");
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

	sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (!sockfd) err(1, "socket");

	if (bind(sockfd, (struct sockaddr *) &name, SUN_LEN(&name)) < 0)
		err(1, "bind");
	atexit(cleanup_socket);

	EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, &connection_handler);
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0) abort();
}

int main(int argc, char *argv[])
{
	if (0 && daemon(0, 0) < 0) {
		fprintf(stderr, "Unable to daemonize");
		exit(EX_OSERR);
		log_open("/tmp/zzzd.log"); /* XXX insecure, for testing only */
	} else {
		log_open("/dev/stderr");
	}

	if ((kqfd = kqueue()) < 0) abort();

	setup_socket();
	setup_signal_handlers();
	main_loop();
	exit(EXIT_SUCCESS);
}
