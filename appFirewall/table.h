
#ifndef table_h
#define table_h

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef unsigned long Key;

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


Hashtable* hashtable_new(int hint);
void hashtable_free(Hashtable *table);
void* hashtable_remove(Hashtable *table, const char* key_string);
void* hashtable_get(Hashtable *table, const char* key_string);
void* hashtable_put(Hashtable *table, const char* key_string, void *value);
unsigned long hash(const char *str);

#endif
