//
//  dtrace.h
//  appFirewall
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dtrace_h
#define dtrace_h

#include <stdio.h>
#include <pthread.h>
#include "util.h"
#include "helper.h"
#include "pid_conn_info.h"
#include "table.h"

#define DTRACE_PORT 4
#define DTRACE_CACHE_SIZE 1024

void *dtrace_listener(void *ptr);
void start_dtrace_listener(void);
void stop_dtrace_listener(void);
int lookup_dtrace(conn_raw_t *c, char* name);

#endif /* dtrace_h */
