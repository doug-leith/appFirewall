//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef table_h
#define table_h

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "util.h"

typedef uint32_t Key;

typedef struct Bucket {
  struct Bucket *link;
  Key key; // hash of key_string
  char* key_string;
  void *value; 
} Bucket;

typedef struct {
	uint32_t size;
	Bucket **buckets;
} Hashtable;


Hashtable* hashtable_new(size_t hint);
void hashtable_free(Hashtable *table);
void* hashtable_remove(Hashtable *table, const char* key_string);
void* hashtable_get(Hashtable *table, const char* key_string);
void* hashtable_put(Hashtable *table, const char* key_string, void *value);
Key hash(const char *str);
void dump_hashtable(Hashtable *table);

#endif
