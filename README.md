# libipc

libipc is an IPC mechanism for C programs. It is under heavy development
and the documentation has not been written yet.

It currently runs on FreeBSD and Linux, and I will accept patches to
run on other POSIX-like systems.

Building on FreeBSD
-----------------

Run "make" to build everything.

Building on Linux
-----------------

1. Install libkqueue
2. Run:
```
make CFLAGS="-I/usr/include/kqueue -D_BSD_SOURCE" LDADD="-lkqueue -ldl"
```
