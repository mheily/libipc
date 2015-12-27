#!/bin/sh
#
# Copyright (c) 2015 Mark Heily <mark@heily.com>
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

make clean all || exit

#cd ../src
#make clean ipcd || exit
#./ipcd &
#ipcd_pid=$?
#sleep 1 # let it have time to bind() and so forth
#echo "launched ipcd on pid $ipcd_pid"

cd ../testing
./pingpong-server &
server_pid=$?
echo "launched pingpong-server on pid $server_pid"

# Ensure the server has time to bind to the name
sleep 3

./pingpong-client
kill $server_pid
#kill $ipcd_pid
