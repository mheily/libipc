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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/un.h>
#include <unistd.h>

#include <sys/event.h>

#include "../include/ipc.h"
#include "ipc_private.h"
#include "fdpass.h"
#include "log.h"

static int validate_service_name(const char *service);
static int setup_directories(char *statedir, mode_t mode);

/* Types of kevent callbacks */
enum {
	event_type_client_read,
	event_type_client_accept,
};

struct client_connection {
	SLIST_ENTRY(client_connection) sle;
	int fd;
};

struct ipc_server {
	int pollfd;
	int listenfd;
	struct sockaddr_un sock;
	SLIST_HEAD(, client_connection) clients;
};

static int
mkdir_p(const char *path, mode_t mode)
{
	int rv;

	rv = access(path, X_OK);
	if (rv == 0) return(0);
	if (errno != ENOENT) {		
		rv = IPC_CAPTURE_ERRNO;
		log_errno("access(2) of %s", path);
		return rv;
	}
	if (mkdir(path, mode) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("mkdir(2) of %s", path);
		return rv;
	}			
	return 0;
}

static int
setup_directories(char *statedir, mode_t mode)
{
	char path[PATH_MAX];
	int len;
	int rv;

	rv = mkdir_p(statedir, mode);
	if (rv < 0) {
		return rv;
	}

	len = snprintf(path, sizeof(path), "%s/services", statedir);
	if (len >= sizeof(path) || len < 0) {
		return -IPC_ERROR_NAME_TOO_LONG;
	}

	rv = mkdir_p(path, mode);
	if (rv < 0) {
		return rv;
	}

	len = snprintf(path, sizeof(path), "%s/pidfiles", statedir);
	if (len >= sizeof(path) || len < 0) {
		return -IPC_ERROR_NAME_TOO_LONG;
	}

	rv = mkdir_p(path, mode);
	if (rv < 0) {
		return rv;
	}

	return 0;
}

static int
bind_to_name(struct ipc_server *server, const char *statedir, const char *name)
{
	struct sockaddr_un *sock = &server->sock;
	int fd = -1;
	int len;
	int rv;

	sock->sun_family = AF_LOCAL;
	len = snprintf(sock->sun_path, sizeof(sock->sun_path),
			"%s/services/%s", statedir, name);
	if (len >= sizeof(sock->sun_path) || len < 0) {
		log_error("buffer allocation error");
		return -IPC_ERROR_NAME_TOO_LONG;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("socket(2)");
		return rv;
	}

	if (bind(fd, (struct sockaddr *) sock, SUN_LEN(sock)) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("bind(2)");
		(void) close(fd);
		return rv;
	}

	log_debug("service name `%s' bound to server fd %d", name, fd);

	/* TODO: write a pidfile to statedir/pidfiles using the pidfile_* functions */

	return fd;
}

static int
get_statedir(int domain, char *buf, size_t len)
{
	int rv;
	if (domain == IPC_DOMAIN_SYSTEM) {
		(void)strncpy(buf, "/var/run/ipc", len);
		if (getuid() == 0) {
			rv = setup_directories(buf, 0755);
			if (rv < 0) {
				log_error("directory setup failed");
				return rv;
			}
		} else {
			/* TODO: verify that statedir exists */
		}

		return 0;
	} else if (domain == IPC_DOMAIN_USER) {
		char *home = getenv("HOME");
		if (!home)
			return -IPC_ERROR_NAME_INVALID;
		rv = snprintf(buf, len, "%s/.ipc", home);
		if (rv >= len || rv < 0)
			return -IPC_ERROR_NAME_TOO_LONG;
		rv = setup_directories(buf, 0755);
		if (rv < 0)
			return rv;

		return 0;
	} else {
		log_error("unsupported domain: %d", domain);
		return -IPC_ERROR_ARGUMENT_INVALID;
	}
}

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

struct ipc_server * VISIBLE
ipc_server()
{
	struct ipc_server *srv = malloc(sizeof(*srv));

	if (!srv) return NULL;
	srv->pollfd = kqueue();
	if (!srv->pollfd) {
		free(srv);
		return NULL;
	}
	srv->listenfd = -1;
	SLIST_INIT(&srv->clients);
	return srv;
}

void VISIBLE
ipc_server_free(struct ipc_server *server)
{
	struct client_connection *client, *client_tmp;

	if (server) {
		if (server->pollfd >= 0) {
			close(server->pollfd);
		}
		if (server->listenfd >= 0) {
			close(server->listenfd);
			unlink(server->sock.sun_path);
		}
	    SLIST_FOREACH_SAFE(client, &server->clients, sle, client_tmp) {
	    	close(client->fd);
	    	free(client);
	    }
		free(server);
	}
}

int VISIBLE
ipc_server_get_pollfd(struct ipc_server *server)
{
	return server->pollfd;
}

int VISIBLE
ipc_server_bind(struct ipc_server *server, int domain, const char *name)
{
	struct kevent kev;
	char statedir[PATH_MAX];
	int rv = 0;
	int fd;

	rv = validate_service_name(name);
	if (rv < 0) {
		log_error("invalid service name");
		return rv;
	}

	rv = get_statedir(domain, statedir, sizeof(statedir));
	if (rv < 0) {
		log_error("unable to get statedir");
		return rv;
	}

	fd = bind_to_name(server, statedir, name);
	if (fd < 0) {
		log_error("failed to bind");
		return fd;
	}

	log_info("bound to `%s' on fd %d", name, fd);

	if (listen(fd, 1024) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("listen(2) on %d", fd);
		close(fd);
		return rv;
	}

	server->listenfd = fd;

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)event_type_client_accept);
	if (kevent(server->pollfd, &kev, 1, NULL, 0, NULL) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("kevent(2)");
		close(fd);
		server->listenfd = -1;
		return rv;
	}

	return 0;
}

int VISIBLE
ipc_connect(int domain, const char *service)
{
	char statedir[PATH_MAX];
	struct sockaddr_un sock;
	int len;
	int fd = -1;
	int rv = 0;

	rv = validate_service_name(service);
	if (rv < 0) {
		return rv;
	}

	rv = get_statedir(domain, statedir, sizeof(statedir));
	if (rv < 0)
		return rv;

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path),
			"%s/services/%s", statedir, service);
	if (len >= sizeof(sock.sun_path)) {
		return -IPC_ERROR_NAME_TOO_LONG;
	}
	if (len < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("socket(2)");
		return rv;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("socket(2)");
		return rv;
	}

	if (connect(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("connect(2) to %s", sock.sun_path);
		close(fd);
		return rv;
	}

	log_debug("service `%s' connected to fd %d", service, fd);

	return fd;
}

static int
ipc_accept(struct ipc_server *server) {
	struct kevent kev;
	struct sockaddr sa;
	socklen_t sa_len;
	int client_fd;
	int rv;

	log_debug("waiting for a connection");
	client_fd = accept(server->listenfd, &sa, &sa_len);
	if (client_fd < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("accept(2)");
		return rv;
	}

	struct client_connection *conn;
	conn = malloc(sizeof(*conn));
	if (!conn) {
		log_error("out of memory");
		close(client_fd);
		return -IPC_ERROR_NO_MEMORY;
	}
	conn->fd = client_fd;
	SLIST_INSERT_HEAD(&server->clients, conn, sle);

	EV_SET(&kev, client_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)event_type_client_read);
	if (kevent(server->pollfd, &kev, 1, NULL, 0, NULL) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("kevent(2)");
		SLIST_REMOVE_HEAD(&server->clients, sle);
		free(conn);
		return rv;
	}

	log_debug("accepted a connection on fd %d", client_fd);

	return client_fd;
}

int VISIBLE
ipc_server_dispatch(struct ipc_server *server, int (*cb)(int, char *, size_t))
{
	struct kevent kev;
	struct ipc_message_header hdr;
	int client;
	int rv;
	ssize_t bytes;

	rv = kevent(server->pollfd, NULL, 0, &kev, 1, NULL);
	if (rv < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("kevent(2)");
		return rv;
	}
	if (rv == 0) {
		log_debug("spurious wakeup; no events pending");
		return 0;
	}

	switch ((int) kev.udata) {
	case event_type_client_accept:
		client = ipc_accept(server);
		if (client < 0) {
			log_error("ipc_accept failed");
			return client;
		}
		return 0;

	case event_type_client_read:
		client = kev.ident;
		log_debug("pending data on fd %d", client);
		break;

	default:
		log_error("bad event type: %d", (int )kev.udata);
		return -1;
	}

	/* Read a partial header to determine the request size and method ID */
	bytes = recv(client, &hdr, sizeof(hdr), MSG_PEEK);
	if (bytes < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("recv(2) on %d", client);
		close(client);
		return rv;
	}
	if (bytes < sizeof(hdr)) {
		rv = -IPC_ERROR_ARGUMENT_INVALID;
		log_error("short read; expected %zu, got %zu",
				sizeof(hdr), bytes);
		close(client);
		return rv;
	}
	if (hdr._ipc_bufsz > IPC_MESSAGE_SIZE_MAX) {
		rv = -IPC_ERROR_ARGUMENT_INVALID;
		log_error("message exceeds maximum allowable length");
		close(client);
		return rv;
	}

	log_debug("peek: message size=%zu method=%d\n", hdr._ipc_bufsz, hdr._ipc_method);

	// Read the complete request
	char *request;
	size_t request_sz = hdr._ipc_bufsz;

	request = malloc(request_sz);
	if (!request) {
		rv = -IPC_ERROR_NO_MEMORY;
		log_error("unable to allocate request buffer");
		close(client);
		return rv;
	}

	bytes = read(client, request, request_sz);
	if (bytes < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("read(2) on %d", client);
		close(client);
		return rv;
	}
	if (bytes < request_sz) {
		rv = -IPC_ERROR_ARGUMENT_INVALID;
		log_error("short read; expected %zu, got %zu",
				request_sz, bytes);
		close(client);
		return rv;
	}

	rv = (*cb)(client, request, request_sz);
	free(request);

	return rv;
}

int VISIBLE
ipc_close(int s)
{
	struct sockaddr_un sa;
	socklen_t sa_len = sizeof(sa);
	int rv;

	rv = getsockname(s, (struct sockaddr *) &sa, &sa_len);
	if (rv < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("getsockname(2)");
		return rv;
	}
	if (strlen(sa.sun_path) > 0) {
		rv = unlink(sa.sun_path);
		if (rv < 0) {
			rv = IPC_CAPTURE_ERRNO;
			log_errno("unlink(2) of %s", sa.sun_path);
			return rv;
		}
	}

	/* TODO: remove the pidfile from statedir/pidfiles using the pidfile_* functions */

	return 0;
}

int VISIBLE
ipc_getpeereid(int s, uid_t *uid, gid_t *gid)
{
	int rv = 0;
	if (getpeereid(s, uid, gid) < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("getpeereid(2)");
	}
	return rv;
}

int VISIBLE
ipc_openlog(const char *ident, const char *path)
{
	return log_open(ident, path);
}


const char * VISIBLE
ipc_strerror(int code)
{
	switch (code * -1) {
	case IPC_ERROR_NAME_TOO_LONG:
		return "The name of a service is too long to fit in a buffer";
	case IPC_ERROR_NAME_INVALID:
		return "Invalid characters in a name";
	case IPC_ERROR_ARGUMENT_INVALID:
		return "Invalid argument";
	case IPC_ERROR_NO_MEMORY:
		return "Memory allocation failed";
	case IPC_ERROR_METHOD_NOT_FOUND:
		return "Method not found";
	case IPC_ERROR_CONNECTION_FAILED:
		return "Connection failed";
	}
	if (code < -1000) {
		return strerror((code * -1) - 1000);
	}
	return "Unknown error";
}
