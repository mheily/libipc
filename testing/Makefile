CFLAGS+=-I../include -I../src -DDEBUG -g -O0
TESTS= pingpong-server

all: $(TESTS)

clean:
	rm -f $(TESTS)

pingpong-server:
	$(CC) $(CFLAGS) -o pingpong-server pingpong-server.c ../src/zzz.c ../src/log.c
