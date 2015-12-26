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

#ifndef _ZZZ_H_
#define _ZZZ_H_

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The maximum identifier length of an IPC service */
#define ZZZ_MAX_NAME_LEN 63

#define ZZZ_FUNC(_a) ((void (*)(void *)) _a)

enum {
	ZZZ_BIND_OP, ZZZ_CONNECT_OP,
} ZZZ_OP_CODES;

typedef struct {
	char *name; /** Example: "myapp.my_procedure" */
	size_t namelen; /** The length of <name> plus the NUL terminator */
	int fd; /** The socket descriptor created by the client */
	int connected; /** If 1, the connection is active */
	char *call_sig; /** Call signature */
	char *ret_sig; /** Return signature */
/// ??? uint64_t zb_handle;
}*zzz_connection_t;

/** Service binding */
typedef struct {
	int fd; /** Socket descriptor to listen for new connections */
	char *name; /** Example: "myapp.my_procedure" */
	size_t namelen; /** The length of <name> plus the NUL terminator */
	uid_t permit_uid; /** UID allowed to connect */
	gid_t permit_gid; /** GID allowed to connect */
//	mode_t  permit_mode; 	/** Determine permissions for UID, GID, and other */
//	char    *call_sig;		/** Call signature */
//	char    *ret_sig;       /** Return signature */
//	void    (*cb_func)(void *);
}*zzz_binding_t;

/*# An in-progress operation */
typedef struct zzz_ipc_operation_s {
	int opcode;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	char name[ZZZ_MAX_NAME_LEN];
	size_t namelen;
	int server_fd;
	int client_fd;
} zzz_ipc_operation_t;

/** 
 Bind to a procedure name in the global namespace. Example: "myapp.my_procedure"
 */
zzz_binding_t zzz_bind(const char *name);

/** Accept an incoming IPC request. */
int zzz_accept(zzz_ipc_operation_t *iop, zzz_binding_t bnd);

/** Connect to an IPC service. Example: "com.example.myservice" */
zzz_connection_t zzz_connect(const char *service);

/** Invoke a method of the remote object. Example: "com.example.myservice" */
//int zzz_invoke(zzz_connection_t _conn, const char *method);

void zzz_binding_free(zzz_binding_t);
void zzz_connection_free(zzz_connection_t);

#endif /* _ZZZ_H */
