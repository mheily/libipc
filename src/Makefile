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

include ../install-dir.mk

libipc_SOURCES=ipc.c log.c fdpass.c
libipc_OBJS=ipc.o log.o fdpass.o
libipc_SONAME=libipc.so.1
libipc_REALNAME=libipc.so.1.0.1
CFLAGS+=-I../include
CFLAGS+=-Wall -Werror

all: $(libipc_REALNAME)

$(libipc_REALNAME): $(libipc_SOURCES) fdpass.h ipc_private.h log.h
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) ipc.c
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) log.c
	$(CC) -c -fpic -fvisibility=hidden $(CFLAGS) fdpass.c
	$(CC) -shared -fvisibility=hidden -Wl,-soname,$(libipc_SONAME) $(LDFLAGS) \
		-o $(libipc_REALNAME) $(libipc_OBJS) $(LDADD)
	#
	# KLUDGE: copypasta from above, to build a debug version
	#
	rm -f $(libipc_OBJS)
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG ipc.c
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG log.c
	$(CC) -c -fpic $(CFLAGS) -g -O0 -DDEBUG fdpass.c
	$(CC) -shared $(LDFLAGS) -o libipc_debug.so $(libipc_OBJS) $(LDADD)
	
check: $(libipc_REALNAME)
	cd ../testing && ./test-harness.sh

clean:
	rm -f *.so *.so.* $(libipc_OBJS)

install:
	$(INSTALL) -s -m 755 $(libipc_REALNAME) $$DESTDIR$(LIBDIR)
	$(INSTALL) -ls $(libipc_REALNAME) $$DESTDIR$(LIBDIR)/libipc.so.1
	$(INSTALL) -ls $(libipc_REALNAME) $$DESTDIR$(LIBDIR)/libipc.so
	$(INSTALL) -m 755 ipcc/ipcc.rb $$DESTDIR$(BINDIR)/ipcc

uninstall:
	rm -f $$DESTDIR$(LIBDIR)/$(libipc_REALNAME) \
		$$DESTDIR$(LIBDIR)/libipc.so.1 \
		$$DESTDIR$(LIBDIR)/libipc.so \
		$$DESTDIR$(BINDIR)/ipcc
		

.PHONY: check install uninstall
