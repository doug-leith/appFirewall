//
//  is_blocked.h
//  appFirewall
//


#ifndef is_blocked_h
#define is_blocked_h

#include <stdio.h>
#include "connection.h"

int is_blocked(bl_item_t *c);
int blocked_status(bl_item_t *c);
int is_white(bl_item_t *c);

#endif /* is_blocked_h */
