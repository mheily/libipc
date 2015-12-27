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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The maximum identifier length of an IPC service */
#define IPC_SERVICE_NAME_MAX 255

enum {
	IPC_ERROR_NAME_TOO_LONG = 1, /* The name of a service is too long to fit in a buffer */
	IPC_ERROR_IPCD_CONNECTION_FAILED = 2, /* Unable to talk to ipcd */
	IPC_ERROR_IPCD_BAD_RESPONSE = 3, /* Bad response from ipcd(8) */
	IPC_ERROR_NAME_INVALID = 4, /* Invalid characters in a name */
	IPC_ERROR_ARGUMENT_INVALID = 5, /* An invalid function argument was supplied */
};

enum {
	IPC_DOMAIN_SYSTEM = 1, /* Allows communication with the entire OS */
	IPC_DOMAIN_USER = 2,   /* Allows communication for programs belonging to the current user */
} IPC_DOMAIN_TYPES;

/** 
 Bind to a procedure name in the global namespace. Example: "myapp.my_procedure"
 */
int ipc_bind(int domain, const char *service, int version);

/** Accept an incoming IPC request. */
int ipc_accept(int s);

/** Connect to an IPC service. Example: "com.example.myservice" */
int ipc_connect(int domain, const char *service, int version);

/** Get the credentials of the client */
int ipc_getpeereid(int s, uid_t *uid, gid_t *gid);

/* TODO:

// wrap the FD sending functions
int ipc_send_fd(int s, int fd);
int ipc_recv_fd(int s);

 */
#endif /* _IPC_H */
