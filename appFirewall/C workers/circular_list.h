//
//  circular_list.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef circular_list_h
#define circular_list_h

#include <stdio.h>
#include "table.h"
#include "util.h"

//#define MAXLIST 2048
#define DEFAULT_LIST 2048
typedef struct list_t {
	//void* list[MAXLIST];
	void** list;
	size_t list_start, list_size, maxsize;
	Hashtable *htab; // hash table of pointers intlist for fast lookup
	char* (*hash)(const void* item); // hash function for table
	int (*cmp)(char* (*hash)(const void* item),const void* item1, const void* item2); // returns 1 if items match
	int circular; // is list circular ?
	char list_name[STR_SIZE];
} list_t;
#define LIST_INITIALISER {NULL,0,0,0,NULL,NULL,NULL,0,{0}}

void* in_list(list_t *l, const void *item, int debug);
ssize_t find_item_row(list_t *l, const void* item);
void add_item_to_htab(list_t *l, void *item);
void del_from_htab(list_t *l, const void *item);
void* add_item(list_t *l, void* item, size_t item_size);
int del_item(list_t *l, const void* item);
size_t get_list_size(list_t *l);
void* get_list_item(list_t *l, size_t row);
void init_list(list_t *l, char* (*hash)(const void* item), int (*cmp)(char* (*hash)(const void* item),const void* item1, const void* item2), int circular, ssize_t size, char* name);
void free_list(list_t *l);
void save_list(list_t *l, char* path, size_t item_size, uint8_t file_version);
int load_list(list_t *l, char* path, size_t item_size, uint8_t file_version);
void clear_list(list_t *l);
void sort_list(list_t *l, int (*sort_cmp)(const void *, const void *));
void deep_copy_list(list_t *l1, list_t *l2, size_t item_size);

#endif /* circular_list_h */
