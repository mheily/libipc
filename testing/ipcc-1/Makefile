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
CFLAGS+=-I../../include -I. -DDEBUG -g -O0
LDADD+=../../src/log.c -lipc_debug


IPCC= 	../../src/ipcc/ipcc.rb

all: clean
	$(IPCC) --c-out=. com.example.my.ipc
	$(CC) $(CFLAGS) $(LDFLAGS) -o test-server *.skeleton.c server.c $(LDADD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test-client *.stub.c client.c $(LDADD)

check:
	./test-harness.sh

clean:
	rm -f *.stub.c *.stub.h
	rm -f *.skeleton.c *.skeleton.h
	rm -f test-server test-client

.PHONY: clean
