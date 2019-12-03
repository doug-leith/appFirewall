//
//  dns_conn_cache.h
//  appFirewall
//
//  Created by Doug Leith on 03/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dns_conn_cache_h
#define dns_conn_cache_h

#include <stdio.h>
#include "circular_list.h"
#include "connection.h"

void init_dns_conn_list(void);
void add_dns_conn(char* domain, char* name);
void dump_dns_conn_list(void);
char* guess_name(char* domain, double* confidence);
void save_dns_conn_list(void);
void load_dns_conn_list(void);

#endif /* dns_conn_cache_h */
