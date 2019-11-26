//
//  is_blocked.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef is_blocked_h
#define is_blocked_h

#include <stdio.h>
#include "connection.h"

//swift
int_sw is_blocked(bl_item_t *c);
int_sw blocked_status(bl_item_t *c);
int_sw is_white(bl_item_t *c);

#endif /* is_blocked_h */
