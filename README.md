# libipc

libipc is a mechanism that allows a C program to call a function that is
executed in a different program. It is implemented as a thin layer on top
of Unix-domain sockets.

It is under heavy development and the documentation has not been written yet.

It currently runs on FreeBSD and Linux, but should be portable to
other POSIX-like systems.

What currently works:
* using the ipcc IDL compiler to generate code
* declaring functions that take integers or strings
* embedding an IPC server into an existing daemon
* calling remote functions as a client

What is planned for the future:
* support for passing file descriptors between processes
* declaring structures and passing them as function arguments
* merging [the StateD library](https://github.com/mheily/stated) into libipc,
and using it to provide support for variables
* thread safety
* a convenience function to call from main() that provides a complete IPC server-in-a-box.
This would be for daemons that are purely for IPC, and don't have their own run loop.

What would be desired, but is not on the roadmap yet:
* asynchronous function calls
* kernel support for performance optimizations

# Building from source code

## Building on FreeBSD

Run "make" to build everything.

##Building on Linux

1. Install libkqueue
2. Run:
```
make CFLAGS="-I/usr/include/kqueue -D_BSD_SOURCE" LDADD="-lkqueue -ldl -lpthread"
```

# Usage

Refer to the [Developer's Guide](http://mheily.github.io/libipc/) for
information about using this library.

# Contact information

There is a [libipc-devel mailing list](https://groups.google.com/d/forum/libipc-devel) dedicated
to discussion of this library. 

