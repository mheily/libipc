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

#include "../include/ipc.h"
#include "ipc_private.h"
#include "fdpass.h"
#include "log.h"

static int connect_to_zzzd();
static int validate_service_name(const char *service);

static int
validate_service_name(const char *service)
{
	size_t namelen;
	int rv = 0;

	namelen = strlen(service);
	if (namelen > IPC_SERVICE_NAME_MAX) {
		return -IPC_ERROR_NAME_TOO_LONG;
	}
	if (namelen > 0 && service[0] == '.') {
		return -IPC_ERROR_NAME_INVALID;
	}
	for (int i = 0; i < namelen; i++) {
		if (service[i] == '/') {
			return -IPC_ERROR_NAME_INVALID;
		}
	}

	return rv;
}

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

int
ipc_bind(int domain, const char *name, int version)
{
	int zzzd_fd;
	ipc_operation_t iop;
	int rv = 0;
	int fd;

	(void)version; //TODO: include this in the filename

	rv = validate_service_name(name);
	if (rv < 0) {
		return rv;
	}

	switch (domain) {
	case IPC_DOMAIN_SYSTEM:
		//TODO
		break;
	case IPC_DOMAIN_USER:
		//TODO
		break;
	default:
		return -IPC_ERROR_ARGUMENT_INVALID;
	}

	zzzd_fd = connect_to_zzzd();
	if (zzzd_fd < 0) {
		return -IPC_ERROR_IPCD_CONNECTION_FAILED;
	}

	iop.opcode = IPC_OP_BIND;
	strncpy(iop.name, name, sizeof(iop.name));
	if (write(zzzd_fd, &iop, sizeof(iop)) < sizeof(iop)) {
		rv = CAPTURE_ERRNO;
		log_errno("write(2)");
		close(zzzd_fd);
		return rv;
	}

	char c[1];
	socklen_t buflen = 1;
	fd = fdpass_recv(zzzd_fd, &c, &buflen);
	if (fd < 0 || buflen != 1) {
		log_error("error receiving the listening socket");
		close(zzzd_fd);
		return -IPC_ERROR_IPCD_BAD_RESPONSE;
	}

	close(zzzd_fd);

	log_info("bound to `%s' on fd %d", name, fd);

	if (listen(fd, 1024) < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("listen(2) on %d", fd);
	}

	return fd;
}

int
ipc_connect(int s, const char *service, int version)
{
	struct sockaddr_un sock;
	int len;
	int fd = -1;
	int rv = 0;

	(void)version; //TODO: include this in the filename

	rv = validate_service_name(service);
	if (rv < 0) {
		return rv;
	}

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/services/%s", "/tmp/zzz", service);
	if (len >= sizeof(sock.sun_path)) {
		return -IPC_ERROR_NAME_TOO_LONG;
	}
	if (len < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("socket(2)");
		return rv;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("socket(2)");
		return rv;
	}

	if (connect(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("connect(2)");
		close(fd);
		return rv;
	}

	log_debug("service `%s' connected to fd %d", service, fd);

	return fd;
}

/* To be done in the server right after calling accept(1) to get a new connection */
int ipc_accept(int s) {
	struct sockaddr sa;
	socklen_t sa_len;
	int client_fd;
	int rv;

	client_fd = accept(s, &sa, &sa_len);
	if (client_fd < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("accept(2) on %d", s);
		return rv;
	}

	log_debug("accepted a connection on fd %d", client_fd);

	return client_fd;
}

int
ipc_getpeereid(int s, uid_t *uid, gid_t *gid)
{
	int rv = 0;
	if (getpeereid(s, uid, gid) < 0) {
		rv = CAPTURE_ERRNO;
		log_errno("getpeereid(2)");
	}
	return rv;
}
