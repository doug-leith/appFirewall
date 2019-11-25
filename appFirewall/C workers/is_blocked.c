//
//  is_blocked.c
//  appFirewall
//

#include "is_blocked.h"
#include "whitelist.h"
#include "hostlists.h"
#include "blocklists.h"
#include "blocklist.h"

int blocked_status(bl_item_t *c) {
	int blocked=0;
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
	return blocked;
}

int is_white(bl_item_t *c) {
	return (in_whitelist_htab(c,0)!=NULL);
}

int is_blocked(bl_item_t *c) {
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

