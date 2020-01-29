//
//  pgrep.h
//  appFirewall
//
//  Created by Doug Leith on 14/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef pgrep_h
#define pgrep_h

#include <stdio.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include "util.h"
#include "pid_conn_info.h"

int find_proc(const char* target);

#endif /* pgrep_h */
