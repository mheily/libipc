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
#include <unistd.h>
#include "fdpass.h"
#include "zzz.h"
#include "log.h"

/* KLUDGE: not sure why this isn't visible */
int getpeereid(int, uid_t *, gid_t *);

static int connect_to_zzzd();
static zzz_connection_t zzz_connection_alloc(const char *name);

static int connect_to_zzzd() {
	struct sockaddr_un saun;
	int fd;
	int rv;
	const char *path = "/tmp/zzz/zzzd.sock"; /* XXX-for testing */

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_errno("socket(2)");
		return -1;
	}

	saun.sun_family = AF_LOCAL;
	strncpy(saun.sun_path, path, sizeof(saun.sun_path));
	rv = connect(fd, (struct sockaddr *) &saun, SUN_LEN(&saun));
	if (rv < 0) {
		log_errno("connect(2)");
		return -1;
	}

	log_info("connected to zzzd");

	return fd;
}

static zzz_connection_t zzz_connection_alloc(const char *service) {
	zzz_connection_t conn;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;
	conn->name = strdup(service);
	if (!conn->name) {
		free(conn);
		return NULL;
	}
	conn->namelen = strlen(conn->name);
	if (conn->namelen > ZZZ_MAX_NAME_LEN) {
		log_error("name too long");
		free(conn->name);
		free(conn);
		return NULL;
	}
	conn->namelen += 1;

	return conn;
}

zzz_binding_t zzz_binding_alloc(const char *name) {
	zzz_binding_t p;
	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->name = strdup(name);
	if (!p->name) {
		free(p);
		return NULL;
	}
	p->namelen = strlen(p->name);
	if (p->namelen > ZZZ_MAX_NAME_LEN) {
		free(p->name);
		free(p);
		return NULL;
	}
	p->namelen += 1;
	return (p);
}

void zzz_binding_free(zzz_binding_t binding) {
	if (!binding)
		return;
	free(binding->name);
	free(binding);
}

zzz_binding_t zzz_bind(const char *name) {
	int zzzd_fd;
	zzz_ipc_operation_t iop;
	zzz_binding_t b;

	b = zzz_binding_alloc(name);
	if (!b) {
		return NULL;
	}
	zzzd_fd = connect_to_zzzd();
	if (zzzd_fd < 0) {
		zzz_binding_free(b);
		return NULL;
	}

	iop.opcode = ZZZ_BIND_OP;
	memcpy(&iop.name, b->name, b->namelen);
	if (write(zzzd_fd, &iop, sizeof(iop)) < sizeof(iop)) {
		log_errno("write(2)");
		zzz_binding_free(b);
		close(zzzd_fd);
		return NULL;
	}

	char c[1];
	socklen_t buflen = 1;
	b->fd = fdpass_recv(zzzd_fd, &c, &buflen);
	if (b->fd < 0 || buflen != 1) {
		log_error("error receiving the listening socket");
		close(zzzd_fd);
		zzz_binding_free(b);
		return NULL;
	}

	close(zzzd_fd);

	log_info("bound to `%s' on fd %d", b->name, b->fd);

	// TODO: move this to zzz_listen() to match BSD sockets
	if (listen(b->fd, 1024) < 0) {
		err(1, "listen");
		close(b->fd);
		//TODO: unlink(sock.sun_path);
		zzz_binding_free(b);
		return NULL;
	}

	return b;
}

zzz_connection_t 
zzz_connect(const char *service)
{
	zzz_connection_t conn;
	struct sockaddr_un sock;
	int len;
	int fd = -1;

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/services/%s", "/tmp/zzz", service);
	if (len >= sizeof(sock.sun_path) || len < 0) {
		log_error("buffer allocation error");
		return NULL;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_errno("socket(2)");
		return NULL;
	}

	if (connect(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		log_errno("connect(2)");
		close(fd);
		return NULL;
	}

	conn = zzz_connection_alloc(service);
	if (!conn) {
		return NULL;
	}
	conn->fd = fd;

	log_debug("service `%s' connected to fd %d", service, fd);

	return conn;
}

int zzz_invoke(zzz_connection_t _conn, const char *method) {
	//TODO:
	return -1;
}

/* To be done in the server right after calling accept(1) to get a new connection */
int zzz_accept(zzz_ipc_operation_t *iop, zzz_binding_t bnd) {
	struct sockaddr sa;
	socklen_t sa_len;
	int client_fd;

	iop->client_fd = accept(bnd->fd, &sa, &sa_len);
	if (iop->client_fd < 0) {
		log_errno("accept(2) on %d", bnd->fd);
		return -1;
	}

	if (getpeereid(iop->client_fd, &iop->uid, &iop->gid) < 0) {
		log_errno("getpeereid(2)");
		close(iop->client_fd);
		iop->client_fd = -1;
		return -1;
	}
	iop->pid = 0; /* DEADWOOD: not portable, hard to support */

	log_debug("accepted a new client connection; uid=%d gid=%d", iop->uid,
			iop->gid);

	return 0;
}

void zzz_connection_free(zzz_connection_t conn) {
	if (!conn)
		return;
	free(conn->name);
	free(conn);
}
