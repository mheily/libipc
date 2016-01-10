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

test_LDFLAGS+=-Wl,-rpath,../../src -L../../src
test_LDFLAGS+=-Wl,-rpath,./ipc -L./ipc
test_CFLAGS+=-std=c99 -I../../include -I. -I./ipc -DDEBUG -g -O0
test_LDADD+=../../src/log.c

test_CFLAGS+=$(CFLAGS)
test_LDFLAGS+=$(LDFLAGS)
test_LDADD+=$(LDADD)

IPCC= 	../../src/ipcc/ipcc.rb
unused_IPC_CONFIG= 	IPC_CONFIG_LIBDIR=. \
		IPC_CONFIG_INCLUDEDIR=. \
		../../src/ipc-config/ipc-config

all: ipc/libipc_com_example_myservice.so test-server test-client

ipc/libipc_com_example_myservice.so:
	mkdir -p ipc
	$(IPCC) --debug \
		--cflags="-I../../include" \
		--ldflags="-Wl,-rpath,../../src -L../../src" \
		--c-out=./ipc com.example.myservice.ipc

test-client:
	$(CC) $(test_CFLAGS) $(test_LDFLAGS) -o test-client client.c $(test_LDADD) -lipc_debug

test-server:
	$(CC) $(test_CFLAGS) -rdynamic $(test_LDFLAGS) -o test-server server.c $(test_LDADD) -lipc_debug

check:
	./test-harness.sh

clean:
	rm -f *.ipc.c *.ipc.h
	rm -f test-server test-client
	rm -rf ./ipc

.PHONY: clean
