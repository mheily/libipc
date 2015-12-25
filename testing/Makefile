CFLAGS+=-I../include -I../src -DDEBUG -g -O0
TESTS= pingpong-server pingpong-client

# Borrow some things from zzzd to avoid the need to create a library
other_src=../src/zzz.c ../src/log.c ../src/fdpass.c

all: zzzd $(TESTS)

clean:
	rm -f $(TESTS)

zzzd:
	cd ../src ; $(MAKE) clean zzzd

pingpong-server:
	$(CC) $(CFLAGS) -o pingpong-server pingpong-server.c $(other_src)

pingpong-client:
	$(CC) $(CFLAGS) -o pingpong-client pingpong-client.c $(other_src)

check:
	./test-harness.sh

.PHONY: zzzd check
