//
//  dtrace.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dtrace_h
#define dtrace_h

#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include "util.h"
#include "helper.h"
#include "connection.h"
#include "circular_list.h"

#define DTRACE_PORT 4

void *dtrace_listener(void *ptr);
void start_dtrace_listener(void);
void stop_dtrace_listener(void);
int lookup_dtrace(conn_raw_t *c, char* name, int* pid);
void set_dtrace_watcher_hook(void (*hook)(void)) ;
int dtrace_error(void);

#endif /* dtrace_h */
