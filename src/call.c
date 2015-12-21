/* Automatically generated -- do not edit */

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
  
#include "zzz.h"
  
#define FLEXARG_MAX 5
  
typedef union {
  char *str;
  uint32_t u32;
  int32_t i32;
} flexarg_t;
  
typedef struct {
  size_t argc;
  flexarg_t arg[FLEXARG_MAX];
} arglist_t;
  
static char * wrapper_s_s(flexarg_t arg0) {
  
  return NULL;
}
static uint32_t wrapper_i_s(flexarg_t arg0) {
  
  return -1;
}
static char * wrapper_s_i(flexarg_t arg0) {
  
  return NULL;
}
static uint32_t wrapper_i_i(flexarg_t arg0) {
  
  return -1;
}
static char * wrapper_s_d(flexarg_t arg0) {
  
  return NULL;
}
static uint32_t wrapper_i_d(flexarg_t arg0) {
  
  return -1;
}

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
  
  return 0;
}
