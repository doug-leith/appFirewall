//
//  blocklists.h
//  appFirewall
//
//  Created by Doug Leith on 14/11/2019.
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
#include "blocklist.h"

#define HTABSIZE 250000

void load_blocklistfile(const char* fname);
void* in_blocklists_htab(bl_item_t *b);

#endif /* blocklists_h */
