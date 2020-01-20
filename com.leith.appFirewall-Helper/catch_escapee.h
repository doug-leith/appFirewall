//
//  catch_escapee.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef catch_escapee_h
#define catch_escapee_h

#include <stdio.h>
#include <unistd.h>
#include <libproc.h>
#include <fcntl.h>
#include "send_rst.h"
#include "util.h"
#include "conn.h"


#define CATCHER_PORT 5

void start_catcher_listener(void);
void stop_catcher(void);

#endif /* catch_escapee_h */
