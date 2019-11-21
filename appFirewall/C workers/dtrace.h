//
//  dtrace.h
//  appFirewall
//


#ifndef dtrace_h
#define dtrace_h

#include <stdio.h>
#include <pthread.h>
#include "util.h"
#include "helper.h"
#include "pid_conn_info.h"
#include "circular_list.h"

#define DTRACE_PORT 4

void *dtrace_listener(void *ptr);
void start_dtrace_listener(void);
void stop_dtrace_listener(void);
int lookup_dtrace(conn_raw_t *c, char* name);

#endif /* dtrace_h */
