//
//  hostlists.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef hostlists_h
#define hostlists_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/errno.h>
#include "util.h"
#include "table.h"
#include "connection.h"

#define HTABSIZE 250000

void init_hosts_list(void);
void* in_hostlist_htab(const char *domain);
void add_hostlist(char * domain);

//swift
int_sw load_hostsfile(const char* fname);

#endif /* hostlists_h */

