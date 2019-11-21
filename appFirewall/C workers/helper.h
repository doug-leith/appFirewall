//
//  helper.h
//  appFirewall
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef helper_h
#define helper_h

#include <stdio.h>
#include "util.h"
//#include "sniffer_blocker.h"
#include "dtrace.h"

#define MAXTRIES 10

void start_listener(void);
void stop_listener(void);

int connect_to_helper(int port);
void start_helper_listeners(void);
void stop_helper_listeners(void);

#endif /* helper_h */
