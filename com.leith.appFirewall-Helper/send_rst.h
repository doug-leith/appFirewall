//
//  send_rst.h
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef send_rst_h
#define send_rst_h

#include <stdio.h>
#include <netinet/in.h>
#include "libnet.h"
#include "util.h"

#define RST_PORT 2

void init_libnet(void);
void rst_accept_loop(void);
void close_rst_sock(void);

#endif /* send_rst_h */
