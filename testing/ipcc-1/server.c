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

#include "../../include/ipc.h"
#include "../../src/log.h"

int
echo(int *ret1, int arg1)
{
	*ret1 = arg1;
	return 0;
}

int main(int argc, char *argv[]) {
	struct ipc_server *server;
	int result;
	int client;
	int rv;
    int i;
	uid_t uid;
	gid_t gid;

	setenv("IPC_LIBDIR", "./ipc", 1);

	log_open("server", "/dev/stderr");
	ipc_openlog("server", "/dev/stderr");

	server = ipc_server();
	if (!server)
		errx(1, "ipc_server()");

	rv = ipc_server_bind(server, IPC_DOMAIN_USER, "com.example.myservice");
	if (rv < 0)
		errx(1, "bind: %s", ipc_strerror(rv));

	/* Do this twice: once to accept a new connection, once to handle the request */
	for (i = 0; i < 2; i++) {
		log_info("waiting for event");

		rv = ipc_server_dispatch(server);
		if (rv < 0)
			errx(1, "ipc_dispatch: %s", ipc_strerror(rv));
	}

	ipc_server_free(server);

	log_notice("success; exiting normally");
	exit(EXIT_SUCCESS);
}
