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
#include "util.h"
#include "pcap_sniffer.h"
#include "send_rst.h"

#define DTRACE_PORT 4

void start_dtrace(int stdout);
void *dtrace(void *ptr);
int exec(char* cmd, int *pipefd, int d_sock2);
void kill_dtrace(void);

#endif /* dtrace_h */
