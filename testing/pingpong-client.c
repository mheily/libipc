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

int main(int argc, char *argv[]) {
	int server;
	char buf[5];
	ssize_t bytes;
	int result;

	log_open("pingpong-client", "/dev/stderr");

	server = ipc_connect(IPC_DOMAIN_USER, "test.ping", 1);
	if (server < 0)
		errx(1, "connect");

	bytes = read(server, &buf, 5);
	if (result < 5)
		err(1, "read: %zu bytes", bytes);

	printf("client got: %s\n", buf);

	exit(EXIT_SUCCESS);
}
