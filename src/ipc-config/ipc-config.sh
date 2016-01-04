#!/bin/sh
#
# Copyright (c) 2016 Mark Heily <mark@heily.com>
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


usage() {
	cat << EOF
usage: ipc-config [MODE] [OPTION] [IPC SERVICES]

mode is one of:
  --client                      output information to build IPC clients
  --server                      output information to build IPC servers

option is one of:
  --cflags                      print the compiler flags  
  --ldflags                     print the linker flags  
  --ldadd                       print additional linker objects 

For more information, visit <https://github.com/mheily/zipzapzop>.
EOF
}

mode=$1
shift
option=$1
shift

if [ -z "$option" -o -z "$mode" ] ; then
	echo "ERROR: required parameters <mode> and <option> are missing"
	usage
	exit 1
fi

# XXX-TEMPORARY
libdir="/usr/local/lib/ipc"
includedir="/usr/local/include/ipc"

#
# Allow overriding directories
#
if [ -n "$IPC_CONFIG_LIBDIR" ] ; then 
	libdir="$IPC_CONFIG_LIBDIR"
fi
if [ -n "$IPC_CONFIG_INCLUDEDIR" ] ; then 
	includedir="$IPC_CONFIG_INCLUDEDIR"
fi

#
# Things only done once per output type
#
case "$mode$option" in
"--client--cflags")
	printf '%s' "-I${includedir}"
	;;
"--client--ldflags")
	;;
"--client--ldadd")
	printf '%s' "-lipc"
	;;
"--server--cflags")
	printf '%s' " -I${includedir}"
	;;
"--server--ldflags")
	printf '%s' " -rdynamic"
	;;
"--server--ldadd")
	printf '%s' "-lipc"
	;;
*)
	echo "invalid mode or option"
	exit 1
esac

#
# Things done once per IPC service
#
for arg in $*
do
  libname=$(echo "$arg" | tr '.' '_')
  case "$mode$option" in
"--client--cflags")
	;;
"--client--ldflags")
	;;
"--client--ldadd")
	printf " ${libdir}/stub-${libname}.so"
	;;
"--server--cflags")
	printf " -include $libname.h"
	;;
"--server--ldflags")
	;;
"--server--ldadd")
	printf " ${libdir}/stub-${libname}.so"
	;;
*)
	echo "invalid mode or option"
	exit 1
esac
done

echo ''
