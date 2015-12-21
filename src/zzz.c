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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "zzz.h"

static int sockfd; /** Connection to zzzd */

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

	return 0;
}

zzz_binding_t zzz_binding_alloc(const char *name)
{
	zzz_binding_t p;
	p = calloc(1, sizeof(*p));
	if (!p) return NULL;
	p->name = strdup(name);
	if (!p->name) { free(p); return NULL; }
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

	/* TODO: communicate to zzzd here */
	return 0;
}

zzz_connection_t
zzz_connection_alloc(const char *name)
{
	zzz_connection_t p;
	p = calloc(1, sizeof(p));
	if (!p) return NULL;
	p->name = strdup(name);
	if (!p->name) { free(p); return NULL; }
	return (p);
}

void
zzz_connection_free(zzz_connection_t conn)
{
	if (!conn) return;
	free(conn->name);
	free(conn);
}
