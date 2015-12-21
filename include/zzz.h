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

#define ZZZ_FUNC(_a) ((void (*)(void *)) _a)

typedef struct {
	char    *name;		/** Example: "myapp.my_procedure" */
	int     connected;	/** If 1, the connection is active */
	char    *call_sig;		/** Call signature */
	char    *ret_sig;       /** Return signature */
	/// ??? uint64_t zb_handle;
} *zzz_connection_t;

typedef struct {
	char    *name;		/** Example: "myapp.my_procedure" */
	uid_t   permit_uid;	/** UID allowed to connect */
	gid_t   permit_gid;	/** GID allowed to connect */
	mode_t  permit_mode; 	/** Determine permissions for UID, GID, and other */
	char    *call_sig;		/** Call signature */
	char    *ret_sig;       /** Return signature */
	void    (*cb_func)(void *);
	// ??? uint64_t zb_handle;
} *zzz_binding_t;

/** Connect to zzzd */
int	zzz_init();

/** 
Bind to a procedure name in the global namespace. Example: "myapp.my_procedure" 
*/
int zzz_bind(zzz_binding_t *binding, const char *name, mode_t mode, const char *call_sig, const char *ret_sig,
		void (*cb_func)(void *));

/** Connect to a procedure name in the global namespace. Example: "myapp.my_procedure" */
int	zzz_connect(zzz_connection_t _conn, const char *_name);

zzz_binding_t zzz_binding_alloc(const char *);
void zzz_binding_free(zzz_binding_t);
/* TODO: chgrp */
static inline int zzz_binding_mode(zzz_binding_t _zzz_bind, mode_t _zzz_mode) {
	_zzz_bind->permit_mode = _zzz_mode;
	return 0;
}

zzz_connection_t zzz_connection_alloc(const char *);
void zzz_connection_free(zzz_connection_t);

#endif /* _ZZZ_H */
