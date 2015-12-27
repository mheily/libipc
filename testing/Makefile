CFLAGS+=-I../include -I../src -DDEBUG -g -O0
TESTS= pingpong-server pingpong-client

# Borrow some things from src/ to avoid the need to create a library
other_src=../src/ipc.c ../src/log.c ../src/fdpass.c

all: ipcd $(TESTS)

clean:
	rm -f $(TESTS)

ipcd:
	cd ../src ; $(MAKE) clean ipcd

pingpong-server:
	$(CC) $(CFLAGS) -o pingpong-server pingpong-server.c $(other_src)

pingpong-client:
	$(CC) $(CFLAGS) -o pingpong-client pingpong-client.c $(other_src)

check:
	./test-harness.sh

.PHONY: ipcd check
