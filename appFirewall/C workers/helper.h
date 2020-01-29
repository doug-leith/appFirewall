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

#define IntallUpdatecmd 1
#define BlockQUICcmd 2
#define UnblockQUICcmd 3
#define StartDNScmd 4
#define StopDNScmd 5
#define QUICStatuscmd 6
#define GetDNSOutputcmd 7

int connect_to_helper(int port,int quiet);
void start_listener(void); // sniffer_blocker.h
void stop_listener(void); // sniffer_blocker.h

// swift interface
void start_helper_listeners(int_sw dtrace, int_sw nstat);
void stop_helper_listeners(void);
char* helper_cmd_install(const char* src_dir, const char* dst_dir, const char* file);
char* unblock_QUIC(void);
char* block_QUIC(void);
int QUIC_status(void);
char* start_dnscrypt_proxy(const char* path);
char* stop_dnscrypt_proxy(void);
char* GetDNSOutput(int *dnscrypt_proxy_stopped, int *dnscrypt_proxy_running);

#endif /* helper_h */
