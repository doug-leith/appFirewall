//
//  helper.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef helper_h
#define helper_h

#include <stdio.h>
#include "util.h"
#include "dtrace.h"
#include "netstats.h"

#define MAXTRIES 10
#define CMD_PORT 6

int connect_to_helper(int port,int quiet);
void start_listener(void); // sniffer_blocker.h
void stop_listener(void); // sniffer_blocker.h

// swift interface
void start_helper_listeners(int_sw dtrace, int_sw nstat);
void stop_helper_listeners(void);
char* helper_cmd_install(const char* src_dir, const char* dst_dir, const char* file);
int unblock_QUIC(void);
int block_QUIC(void);

#endif /* helper_h */
