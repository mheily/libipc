#
# Copyright (c) 2015 Mark Heily <mark@heily.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

libipc_SOURCES=ipc.c log.c fdpass.c
libipc_OBJS=ipc.o log.o fdpass.o
CFLAGS+=-I../include
CFLAGS+=-Wall -Werror

all: libipc.so

libipc.so: $(libipc_SOURCES) fdpass.h ipc_private.h log.h
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) ipc.c
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) log.c
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) fdpass.c
	$(CC) -shared -fvisibility=hidden $(LDFLAGS) -o libipc.so $(libipc_OBJS) $(LDADD)
	# KLUDGE: copypasta from above, to build a debug version
	rm -f $(libipc_OBJS)
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG ipc.c
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG log.c
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG fdpass.c
	$(CC) -shared $(LDFLAGS) -o libipc_debug.so $(libipc_OBJS) $(LDADD)

check: libipc.so
	cd ../testing && ./test-harness.sh

clean:
	rm -f libipc.so $(libipc_OBJS)

.PHONY: check
