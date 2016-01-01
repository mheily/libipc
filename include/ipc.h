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

#ifndef _IPC_H_
#define _IPC_H_

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The maximum identifier length of an IPC service */
#define IPC_SERVICE_NAME_MAX 255

/** The maximum size of an IPC message */
#define IPC_MESSAGE_SIZE_MAX 16384

/** Capture the value of errno in a way that does not overlap with libipc
 * error codes.
 */
#define IPC_CAPTURE_ERRNO (-errno - 1000)

enum {
	IPC_ERROR_NAME_TOO_LONG = 1, /* The name of a service is too long to fit in a buffer */
	IPC_ERROR_NAME_INVALID = 2, /* Invalid characters in a name */
	IPC_ERROR_ARGUMENT_INVALID = 3, /* An invalid function argument was supplied */
	IPC_ERROR_NO_MEMORY = 4, /* Memory allocation failed */
	IPC_ERROR_METHOD_NOT_FOUND = 5,
	IPC_ERROR_CONNECTION_FAILED = 6, /* Client unable to connect to server socket */
};

enum {
	IPC_DOMAIN_SYSTEM = 1, /* Allows communication with the entire OS */
	IPC_DOMAIN_USER = 2,   /* Allows communication for programs belonging to the current user */
} IPC_DOMAIN_TYPES;

/** The basic header fields common to all IPC messages */
struct ipc_message_header {
	  size_t _ipc_bufsz;    /** The total size of the message */
	  int    _ipc_method;   /** The unique ID of the method */
};

/** To allow running multiple IPC server threads, each server keeps a private
 *  variable with context information.
 */
struct ipc_server;

/** An opaque object that encapsulates all server-side functions */
struct ipc_server * ipc_server();

/** Accessor */
int ipc_server_get_pollfd(struct ipc_server *);

/** 
 Bind to a procedure name in the global namespace. Example: "myapp.my_procedure"
 */
int ipc_server_bind(struct ipc_server *server, int domain, const char *service);

/**
 * Free resources associated with a server
 */
void ipc_server_free(struct ipc_server *server);

/** Dispatch an incoming IPC request. */
int ipc_server_dispatch(struct ipc_server *server, int (*cb)(int, char *, size_t));

/** Connect to an IPC service. Example: "com.example.myservice" */
int ipc_connect(int domain, const char *service);

/** Close an IPC socket */
int ipc_close(int s);

/** Get the credentials of the client */
int ipc_getpeereid(int s, uid_t *uid, gid_t *gid);

/** Return a string representing an IPC error code */
const char *ipc_strerror(int code);

/** Open a logfile to capture IPC debugging information */
int ipc_openlog(const char *ident, const char *path);

/* TODO:

// wrap the FD sending functions
int ipc_send_fd(int s, int fd);
int ipc_recv_fd(int s);

 */
#endif /* _IPC_H */
