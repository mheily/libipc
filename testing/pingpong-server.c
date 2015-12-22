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
static zzz_binding_t pingpong_b;

char *handle_ping(char *msg)
{
	return ("pong");
}

void cleanup_pingpong()
{
	zzz_binding_free(pingpong_b);
}

void setup_pingpong()
{
	int result;

	if (zzz_init() < 0) errx(1, "zzz_init()");
	result = zzz_bind(&pingpong_b, "zzzd.ping", 0755, "%s", "%s", ZZZ_FUNC(handle_ping));
	if (result < 0) errx(1, "zzz_bind");
}

int main(int argc, char *argv[])
{
	struct kevent kev;

	log_open("/dev/stderr");

	if ((kqfd = kqueue()) < 0) abort();

	setup_pingpong();

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
		log_error("do something");
	}
	exit(EXIT_SUCCESS);
}
