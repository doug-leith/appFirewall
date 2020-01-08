//
//  dtrace.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dtrace_h
#define dtrace_h

#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <dtrace.h>
#include "util.h"
#include "libnet.h"

#define DTRACE_PORT 4

void start_dtrace(void);
void *dtrace(void *ptr);
int exec(char* cmd, int *pipefd, int d_sock2);
void signal_dtrace(void);
int dtrace_active(void);

#endif /* dtrace_h */
