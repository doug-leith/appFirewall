//
//  cmd.h
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 18/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#ifndef cmd_h
#define cmd_h

#include <stdio.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include "util.h"

#define CMD_PORT 6

#define CMD_TIMEOUT 1 // in secs
#define LONG_CMD_TIMEOUT 10

#define IntallUpdatecmd 1
#define BlockQUICcmd 2
#define UnblockQUICcmd 3
#define StartDNScmd 4
#define StopDNScmd 5
#define QUICStatuscmd 6
#define GetDNSOutputcmd 7

void start_cmd(void);
int set_dns_server(char* dns);
int kill_dnscrypt(void);
void update_intf_dns(void);

#endif /* cmd_h */
