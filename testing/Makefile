CFLAGS+=-Wl,-rpath,../src
CFLAGS+=-I../include -I../src -DDEBUG -g -O0
LDFLAGS+=-L../src
LDADD+=-lipc
TESTS= pingpong-server pingpong-client

all:

clean:
	rm -f $(TESTS)

../src/libipc.so:
	cd ../src && $(MAKE) libipc.so
	
pingpong-server:
	$(CC) $(CFLAGS) $(LDFLAGS) -o pingpong-server pingpong-server.c ../src/log.c $(LDADD)

pingpong-client:
	$(CC) $(CFLAGS) $(LDFLAGS) -o pingpong-client pingpong-client.c ../src/log.c $(LDADD)

check:
	# FIXME: this is broken
	#./test-harness.sh
	cd ipcc-1 && make check

.PHONY: ipcd check
