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

LDFLAGS+=-Wl,-rpath,../../src -L../../src
CFLAGS+=-rdynamic -I../../include -I. -DDEBUG -g -O0
LDADD+=../../src/log.c -lipc_debug


IPCC= 	../../src/ipcc/ipcc.rb

all: clean
	$(IPCC) --cflags="$(CFLAGS)" --ldflags="$(LDFLAGS)" \
		--c-out=. com.example.myservice.ipc
	$(CC) $(CFLAGS) -rdynamic $(LDFLAGS) -o test-server server.c $(LDADD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test-client client.c $(LDADD) ./stub-com_example_myservice.so

check:
	./test-harness.sh

clean:
	rm -f *.ipc.c *.ipc.h
	rm -f test-server test-client

.PHONY: clean
