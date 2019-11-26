//
//  is_blocked.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "is_blocked.h"
#include "whitelist.h"
#include "hostlists.h"
#include "blocklists.h"
#include "blocklist.h"

// we have six(!) lists. (i) user white list, (ii) user black list, (iii) file white list, (iv) file black list for apps, (v) file black list with (app,domain) pairs, (vi) file black list for domains.
// they are applied in that order.  so user whitelist overrules everything, use black list overrules all file lists.

int_sw blocked_status(bl_item_t *c) {
	int blocked=0;
	if (in_blocklist_htab(c,0)!=NULL) {
		// blocked by user
		blocked=1;
		//in_blocklist_htab(&c,1); // dumps hash table, for debugging
	} else if (in_blocklists_htab(c) != NULL) {
		// in block list file -- includes white list, blacklist by app and by (app,domain) pair (in that order)
		blocked = 3;
	} else if (in_hostlist_htab(c->domain) != NULL) {
		// in hosts list i.e. black list domain for all apps
		blocked = 2;
	}
	return blocked;
}

int_sw is_white(bl_item_t *c) {
	// user white list
	return (in_whitelist_htab(c,0)!=NULL);
}

int_sw is_blocked(bl_item_t *c) {
	/*int blocked=0;
	if (in_whitelist_htab(c,0)!=NULL) {
		// whitelisted
		blocked=0;
	} else {
		if (in_blocklist_htab(c,0)!=NULL) { // table lookup, faster !
			blocked=1;
			//in_blocklist_htab(&c,1); // dumps hash table, for debugging
		} else if (in_blocklists_htab(c) != NULL) {
			// in block list file
			blocked = 3;
		} else if (in_hostlist_htab(c->domain) != NULL) {
			// in hosts list
			blocked = 2;
		}
	}
	return blocked;*/
	int blocked;
	if (is_white(c)) {
		blocked = 0;
	} else {
		blocked = blocked_status(c);
	}
	return blocked;
}

