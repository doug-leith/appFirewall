//
//  blocklists.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef blocklists_h
#define blocklists_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/errno.h>
#include "util.h"
#include "table.h"
#include "connection.h"
#include "hostlists.h"

#define HTABSIZE 250000

void* in_blocklists_htab(bl_item_t *b);

//swift
int_sw load_blocklistfile(const char* fname);

#endif /* blocklists_h */
