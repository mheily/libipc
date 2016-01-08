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

/* The maximum number of arguments to a method */
#define IPC_ARGUMENT_MAX 16

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
	IPC_ERROR_MESSAGE_INVALID = 7, /* An invalid message was detected */
};

enum {
	IPC_DOMAIN_SYSTEM = 1, /* Allows communication with the entire OS */
	IPC_DOMAIN_USER = 2,   /* Allows communication for programs belonging to the current user */
} IPC_DOMAIN_TYPES;

/** An IPC message, either a request or a response */
struct ipc_message {
	/* TODO: uint8_t     _ipc_version; */ /** The ABI version of the message */
	uint32_t    _ipc_bufsz;    /** The total size of the message data buffer */
	uint32_t    _ipc_method;   /** The unique ID of the method */
	uint32_t    _ipc_argc;     /** The number of arguments in the message */
	uint32_t    _ipc_argsz[IPC_ARGUMENT_MAX]; /** Size of each argument within the buffer */
};

struct ipc_server;
struct ipc_client;
struct ipc_session;

/** A dummy return type to be used when returning a function pointer. See dlfunc(3) for the reason. */
typedef void (*ipc_function_t)(struct ipc_message);

/** An opaque object that encapsulates all server-side functions */
struct ipc_server * ipc_server();

/** An opaque object that encapsulates all server-side functions */
struct ipc_client * ipc_client();

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
int ipc_server_dispatch(struct ipc_server *server);

/** Connect to an IPC service. Example: "com.example.myservice" */
struct ipc_session * ipc_client_connect(struct ipc_client *client, int domain, const char *service);

/** Get a pointer to the stub function for a method */
ipc_function_t ipc_session_stub(struct ipc_session *session, uint32_t method_id);

/** Close an IPC socket */
int ipc_close(int s);

/** Get the credentials of the client */
int ipc_getpeereid(int s, uid_t *uid, gid_t *gid);

/** Return a string representing an IPC error code */
const char *ipc_strerror(int code);

/** Open a logfile to capture IPC debugging information */
int ipc_openlog(const char *ident, const char *path);

/** Validate the contents of a ipc_message structure */
int ipc_message_validate(struct ipc_message *msg);

/** Get the socket descriptor for a session */
int ipc_session_fd(struct ipc_session *session);

/* TODO:

// wrap the FD sending functions
int ipc_send_fd(int s, int fd);
int ipc_recv_fd(int s);

 */
#endif /* _IPC_H */
