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

#include "../include/ipc.h"
#include "log.h"

static int server_fd;

static void
do_cleanup()
{
	if (server_fd >= 0) ipc_close(server_fd);
}

int main(int argc, char *argv[]) {
	int result;
	int client;
	int rv;
	uid_t uid;
	gid_t gid;

	log_open("pingpong-server", "/dev/stderr");

	server_fd = ipc_bind(IPC_DOMAIN_USER, "test.ping", 1);
	if (server_fd < 0)
		errx(1, "bind: %s", ipc_strerror(server_fd));
	atexit(do_cleanup);

	client = ipc_accept(server_fd);
	if (client < 0)
		errx(1, "accept: %s", ipc_strerror(client));

	rv = ipc_getpeereid(client, &uid, &gid);
	if (rv < 0)
		errx(1, "getpeereid: %s", ipc_strerror(rv));

	log_info("got connection: uid=%d gid=%d", uid, gid);

	if (write(client, "test\0", 5) < 5)
		err(1, "write");

	rv = ipc_close(server_fd);
	if (rv < 0)
		err(1, "close: %s", ipc_strerror(rv));
	server_fd = -1;

	puts("success");
	exit(EXIT_SUCCESS);
}
