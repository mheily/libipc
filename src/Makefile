zzzd_SOURCES=zzzd.c zzz.c log.c call.c
CFLAGS+=-I../include
CFLAGS+=-g -O0 -DDEBUG

all: zzzd

zzzd: $(zzzd_SOURCES)
	$(CC) $(CFLAGS) -o zzzd $(zzzd_SOURCES)

clean:
	rm -f zzzd
