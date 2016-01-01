/*
 * ipc_private.h
 *
 *  Created on: Dec 26, 2015
 *      Author: mark
 */

#ifndef SRC_IPC_PRIVATE_H_
#define SRC_IPC_PRIVATE_H_

/* All symbols are hidden by default. Use this macro to declare symbols
 * that are part of the API.
 */
#define VISIBLE __attribute__ ((visibility ("default")))

/*# An in-progress operation */
typedef struct {
	enum {
		IPC_OP_BIND = 0,
		IPC_OP_CONNECT = 1,
	} opcode;
	char   name[IPC_SERVICE_NAME_MAX];
	size_t namelen;
	uid_t  uid;
	gid_t  gid;
} ipc_operation_t;

/* KLUDGE: not sure why this isn't visible */
int getpeereid(int, uid_t *, gid_t *);

static inline char *
opcode_to_str(int opcode)
{
	switch (opcode) {
	case IPC_OP_BIND:
		return "bind";
	case IPC_OP_CONNECT:
		return "connect";
	default:
		return "invalid-opcode";
	}
}

#endif /* SRC_IPC_PRIVATE_H_ */
