#!/usr/bin/env ruby
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

def ctype(char)
  case char
  when 's'
    'char *'
  when 'i'
    'uint32_t'
  when 'd'
    'int32_t'
  else
    raise 'unknown type: ' + char
  end
end

return_types = %w(s i)
datatypes = %w(s i d)
arg_max = 5

File.open("call.c", "w+") do |f|
  f.puts "/* Automatically generated -- do not edit */"
  f.puts "
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
  
#include \"zzz.h\"
  
#define FLEXARG_MAX #{arg_max}
  
typedef union {
  char *str;
  uint32_t u32;
  int32_t i32;
} flexarg_t;
  
typedef struct {
  size_t argc;
  flexarg_t arg[FLEXARG_MAX];
} arglist_t;
  "
  
  datatypes.each do |dtype|
    return_types.each do |rtype|
      f.puts <<EOF
static #{ctype(rtype)} wrapper_#{rtype}_#{dtype}(flexarg_t arg0) {
  
  return #{rtype == 's' ? 'NULL' : '-1' };
}
EOF
    end
  end

  f.puts <<"EOF"

static int _zzz_call(zzz_connection_t conn, ...)
{
  va_list ap;
  size_t argc;
  arglist_t arglist;
  int i;
  
  argc = strlen(conn->call_sig);
  if (argc != 1) return -1; /* Not supported yet */
  
  va_start(ap, conn);
  i = 0;
  switch (conn->call_sig[i]) {
    case 's':
        arglist.arg[i].str = va_arg(ap, char *);
        break;
      default:
        return -1;
  }
  va_end(ap);
  
  /* TODO: verify that all arguments are non-null */
  
EOF
  
  
f.puts <<"EOF"
  return 0;
}
EOF
end
