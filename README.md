libipc - An IPC mechanism.

Building on Linux
-----------------

1. Install libkqueue
2. Run:
```
make CFLAGS="-I/usr/include/kqueue -D_BSD_SOURCE" LDADD="-lkqueue -ldl"
```
