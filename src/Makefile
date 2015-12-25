zzzd_SOURCES=zzzd.c zzz.c log.c fdpass.c
CFLAGS+=-I../include
CFLAGS+=-g -O0 -DDEBUG

all: zzzd

zzzd: $(zzzd_SOURCES)
	$(CC) $(CFLAGS) -o zzzd $(zzzd_SOURCES)

check:
	cd ../testing && ./test-harness.sh

clean:
	rm -f zzzd

.PHONY: check
