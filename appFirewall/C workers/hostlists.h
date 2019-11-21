//
//  hostlists.h
//  appFirewall
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

#define HTABSIZE 250000

void init_hosts_list(void);
void load_hostsfile(const char* fname);
void* in_hostlist_htab(const char *domain);

#endif /* hostlists_h */

