//
//  dtrace.h
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dtrace_h
#define dtrace_h

#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include "util.h"

#define DTRACE_PORT 4

void start_dtrace(int stdout);
void *dtrace(void *ptr);
int exec(char* cmd, int *pipefd);
void kill_dtrace(void);

#endif /* dtrace_h */
