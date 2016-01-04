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

#include <dlfcn.h>
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

static void service_name_to_libname(char *name);
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
	char *service; /** The IPC service name */
	char *libname;  /** The unique portion of the shared object name; e.g. com_example_myservice */
	int (*dispatch_cb)(int, struct ipc_message *, char *);
	void *skeleton_dlh; /** A handle created by dlopen(3) to the skeleton library */
	int pollfd;
	int listenfd;
	struct sockaddr_un sock;
	int last_error; /** The most recent error code */
	SLIST_HEAD(, client_connection) clients;
};

struct server_connection {
	SLIST_ENTRY(server_connection) sle;
	char *service; /** The name of the service */
	char *libname;  /** The unique portion of the stub library name; e.g. com_example_myservice */
	int domain; /** The IPC domain */
	int fd;    /** Socket descriptor connected to the server */
	void *stub_dlh; /** Handle returned by dlopen() */
};

struct ipc_client {
	SLIST_HEAD(, server_connection) servers;
	int last_error; /** The most recent error code */
};

static void
service_name_to_libname(char *name)
{
	/* Replace illegal characters with '_' */
	/* XXX - this needs to kill ALL illegal characters */
	for (int i = 0; ; i++) {
		if (name[i] == '.') {
			name[i] = '_';
		} else if (name[i] == '\0') {
			break;
		}
	}
}

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
get_library_path(char *dest, size_t sz, const char *libname, const char *prefix)
{
	int len;

	len = snprintf(dest, sz, "./%s-%s.so", prefix, libname);
	if (len >= sz || len < 0) {
		log_error("buffer allocation error");
		return -IPC_ERROR_NAME_TOO_LONG;
	}

	return 0;
}

static int
lookup_dispatch_callback(struct ipc_server *server)
{
	char path[PATH_MAX];
	char ident[255]; /* FIXME: magic number */
	int len;
	int rv;
	void *sym;

	rv = get_library_path(path, sizeof(path), server->libname, "skeleton");
	if (rv < 0) {
		log_error("unable to determine the skeleton path");
		return rv;
	}

	server->skeleton_dlh = dlopen(path, RTLD_LAZY);
	if (!server->skeleton_dlh) {
		server->last_error = IPC_CAPTURE_ERRNO;
		log_errno("dlopen(3) of `%s'", path);
		return server->last_error;
	}

	len = snprintf(ident, sizeof(ident), "ipc_dispatch__%s", server->libname);
	if (len >= sizeof(ident) || len < 0) {
		log_error("buffer allocation error");
		return -IPC_ERROR_NAME_TOO_LONG;
	}

	sym = dlfunc(server->skeleton_dlh, ident);
	if (!sym) {
		server->last_error = IPC_CAPTURE_ERRNO;
		log_errno("dlfunc(3) of `%s'", ident);
		return server->last_error;
	}
	server->dispatch_cb = (int (*)(int, struct ipc_message *, char *)) sym;

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

static int
server_connection_load_stub(struct server_connection *server)
{
	char path[PATH_MAX];
	int rv;

	rv = get_library_path(path, sizeof(path), server->libname, "stub");
	if (rv < 0) {
		log_error("unable to determine the stub path");
		return rv;
	}

	server->stub_dlh = dlopen(path, RTLD_LAZY);
	if (!server->stub_dlh) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("dlopen(3) of `%s'", path);
		return rv;
	}

	return 0;
}

static struct server_connection *
server_connection_new(const char *service)
{
	struct server_connection *conn = calloc(1, sizeof(*conn));

	if (!conn) return NULL;
	conn->service = strdup(service);
	if (!conn->service) {
		free(conn);
		return NULL;
	}
	conn->libname = strdup(service);
	if (!conn->libname) {
		free(conn->service);
		free(conn);
		return NULL;
	}
	service_name_to_libname(conn->libname);
	conn->fd = -1;
	conn->stub_dlh = NULL;

	return conn;
}

static void
server_connection_free(struct server_connection *conn)
{
	if (conn) {
		free(conn->service);
		if (conn->fd >= 0) close(conn->fd);
		if (conn->stub_dlh) dlclose(conn->stub_dlh);
	}
}


struct ipc_client * VISIBLE
ipc_client()
{
	struct ipc_client *client = malloc(sizeof(*client));

	if (!client) return NULL;
	client->last_error = 0;
	SLIST_INIT(&client->servers);
	return client;
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
	srv->service = NULL;
	srv->libname = NULL;
	srv->listenfd = -1;
	srv->skeleton_dlh = NULL;
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
	    free(server->service);
	    free(server->libname);
	    dlclose(server->skeleton_dlh);
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

	free(server->service); /* KLUDGE to avoid adding cleanup handling later */
	server->service = strdup(name);
	if (!server->service) {
		return -IPC_ERROR_NO_MEMORY;
	}

	free(server->libname); /* KLUDGE to avoid adding cleanup handling later */
	server->libname = strdup(name);
	if (!server->libname) {
		return -IPC_ERROR_NO_MEMORY;
	}
	service_name_to_libname(server->libname);

	rv = lookup_dispatch_callback(server);
	if (rv < 0) {
		log_error("unable to lookup dispatcher symbol");
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

struct ipc_session * VISIBLE
ipc_client_connect(struct ipc_client *client, int domain, const char *service)
{
	struct server_connection *conn = NULL;
	char statedir[PATH_MAX];
	struct sockaddr_un sock;
	int len;
	int fd = -1;
	int rv = 0;

	/* Check if we already have a cached entry to the service */
	SLIST_FOREACH(conn, &client->servers, sle) {
		if (conn->domain == domain && strcmp(conn->service, service) == 0) {
			return ((struct ipc_session *) conn);
		}
	}

	rv = validate_service_name(service);
	if (rv < 0) {
		client->last_error = rv;
		goto err_out;
	}

	rv = get_statedir(domain, statedir, sizeof(statedir));
	if (rv < 0) {
		client->last_error = rv;
		goto err_out;
	}

	conn = server_connection_new(service);
	if (!conn) {
		client->last_error = -IPC_ERROR_NO_MEMORY;
		goto err_out;
	}
	if (server_connection_load_stub(conn) < 0) {
		log_error("unable to load the stub library");
		goto err_out;
	}

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path),
			"%s/services/%s", statedir, service);
	if (len >= sizeof(sock.sun_path)) {
		client->last_error = -IPC_ERROR_NAME_TOO_LONG;
		goto err_out;
	}
	if (len < 0) {
		client->last_error = IPC_CAPTURE_ERRNO;
		goto err_out;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		client->last_error = IPC_CAPTURE_ERRNO;
		log_errno("socket(2)");
		goto err_out;
	}

	if (connect(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		client->last_error = IPC_CAPTURE_ERRNO;
		log_errno("connect(2) to %s", sock.sun_path);
		goto err_out;
	}
	conn->fd = fd;

	log_debug("service `%s' connected to fd %d", service, fd);

	SLIST_INSERT_HEAD(&client->servers, conn, sle);

	return (struct ipc_session *) conn;

err_out:
	server_connection_free(conn);
	close(fd);
	return NULL;
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
ipc_server_dispatch(struct ipc_server *server)
{
	struct kevent kev;
	struct ipc_message request;
	int client;
	int rv;
	ssize_t bytes;
	char *buf = NULL;

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

	bytes = read(client, &request, sizeof(request));
	if (bytes < 0) {
		rv = IPC_CAPTURE_ERRNO;
		log_errno("read(2) on %d", client);
		close(client);
		return rv;
	}
	if (bytes < sizeof(request)) {
		rv = -IPC_ERROR_ARGUMENT_INVALID;
		log_error("short read; expected %zu, got %zu",
				sizeof(request), bytes);
		close(client);
		return rv;
	}
	log_debug("request: method=%u body_size=%u", request._ipc_method,
			request._ipc_bufsz
			);

	rv = ipc_message_validate(&request);
	if (rv < 0) {
		log_error("an invalid message was received");
		close(client);
		return rv;
	}

	if (request._ipc_bufsz > 0) {
		buf = malloc(request._ipc_bufsz);
		if (!buf) {
			close(client);
			return -IPC_ERROR_NO_MEMORY;
		}

		bytes = read(client, buf, request._ipc_bufsz);
		if (bytes < 0) {
			rv = IPC_CAPTURE_ERRNO;
			log_errno("read(2) on %d", client);
			free(buf);
			close(client);
			return rv;
		}
		if (bytes < request._ipc_bufsz) {
			rv = -IPC_ERROR_ARGUMENT_INVALID;
			log_error("short read; expected %u, got %ld",
					request._ipc_bufsz, bytes);
			free(buf);
			close(client);
			return rv;
		}
	}

	rv = (*server->dispatch_cb)(client, &request, buf);
	free(buf);

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
ipc_message_validate(struct ipc_message *msg)
{
	int i;
	uint32_t argsz = 0;

	/* TODO: create more specific error codes for these problems */
	if (msg->_ipc_bufsz > IPC_MESSAGE_SIZE_MAX)
		return -IPC_ERROR_NAME_TOO_LONG;
	if (msg->_ipc_argc > IPC_ARGUMENT_MAX)
		return -IPC_ERROR_ARGUMENT_INVALID;

	for (i = 0; i < msg->_ipc_argc; i++) {
		argsz += msg->_ipc_argsz[i];
	}
	if (argsz != msg->_ipc_bufsz) {
		log_error("size mismatch; bufsz=%u argsz=%u", argsz, msg->_ipc_bufsz);
		return -IPC_ERROR_MESSAGE_INVALID;
	}

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
	case IPC_ERROR_MESSAGE_INVALID:
		return "Invalid message structure";
	}
	if (code < -1000) {
		return strerror((code * -1) - 1000);
	}
	return "Unknown error";
}

int VISIBLE
ipc_session_fd(struct ipc_session *session)
{
	if (!session) return -1;
	return ((struct server_connection *)session)->fd;
}
