//
//  circular_list.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "circular_list.h"

int list_cmp(char* (*hash)(const void* item),const void* item1, const void* item2) {
	// default method for comparing list entries, using hash
	char * temp1 = hash(item1);
	char * temp2 = hash(item2);
	int res = (strcmp(temp1,temp2)==0);
	free(temp1); free(temp2);
	return res;
}

void init_list(list_t *l, char* (*hash)(const void* item), int (*cmp)(char* (*hash)(const void* item),const void* item1, const void* item2), int circular, ssize_t size, char* name) {
	l->hash = hash;
	if (cmp) {
		l->cmp = cmp;
	} else {
		l->cmp = list_cmp;
	}
	l->circular = circular;
	l->list_size=0; l->list_start=0;
	if ((size>0) && (size < MAXLIST)) {
		l->maxsize=(size_t)size;
	} else {
		l->maxsize=MAXLIST;
	}
	l->htab = hashtable_new(l->maxsize);
	for (int i=0; i<MAXLIST;i++) l->list[i]=NULL;
	strlcpy(l->list_name,name,STR_SIZE);
}

void free_list(list_t *l) {
	for (size_t i=l->list_start; i<l->list_start+l->list_size;i++) {
		if (l->list[i%l->maxsize]) {
			free(l->list[i%l->maxsize]);
			l->list[i%l->maxsize]=NULL;
		}
	}
	if (l->htab!=NULL) hashtable_free(l->htab);
	l->list_size=0; l->list_start=0;
}

void deep_copy_list(list_t *l1, list_t *l2, size_t item_size) {
	*l1 = *l2;
	l1->htab = hashtable_new(l1->maxsize);
	for (size_t i=l2->list_start; i<l2->list_start+l2->list_size;i++) {
		void* item = malloc(item_size);
		memcpy(item, l2->list[i%l2->maxsize], item_size);
		l1->list[i%l1->maxsize]=item;
		add_item_to_htab(l1, item);
	}
}

void* in_list(list_t *l, const void *item, int debug) {
	// table lookup of list
	if (l->hash == NULL) return NULL;
	char *temp = (l->hash)(item);
	if (debug) { // extra logging requested
		printf("hash='%s'\n", temp);
		dump_hashtable(l->htab);
	}
	void * res = hashtable_get(l->htab, temp);
	free(temp);
	return res;
}

ssize_t find_item_row(list_t *l, const void* item) {
	if (l->hash == NULL) return -1;
	size_t posn;
	for (posn=l->list_start; posn<l->list_start+l->list_size; posn++) {
		if ((l->cmp(l->hash,l->list[posn%l->maxsize],item))) {
				break; //found a match
		}
	}
	return (ssize_t)posn;
}

void add_item_to_htab(list_t *l, void *item) {
	// add item to hash table
	if (l->hash == NULL) return;
	char * temp = (l->hash)(item);
	hashtable_put(l->htab, temp, item);
	free(temp);
}

void del_from_htab(list_t *l, const void *item) {
	if (l->hash == NULL) return;
	char * temp = (l->hash)(item);
	hashtable_remove(l->htab, temp);
	free(temp);
}

void* add_item(list_t *l, void* item, size_t item_size) {
	if (l->hash == NULL) return NULL;
	void* ptr = in_list(l, item, 0);
	if (ptr) {
		DEBUG2("add_item() item %s exists in list %s.\n", l->hash(item),l->list_name);
		return ptr;
	}

	void* it = malloc(item_size);
	memcpy(it,item,item_size); // we take a copy
	if (l->list_size < l->maxsize) {
		size_t end = (l->list_start+l->list_size)%l->maxsize;
		l->list[end] = it;
		l->list_size++;
	} else if (l->circular){
		if (l->list_size > l->maxsize) { // shouldn't happen
			ERR("list size %zu > maxsize %zu for list %s\n",l->list_size,l->maxsize,l->list_name);
			while (l->list_size > l->maxsize) {
				del_from_htab(l, l->list[l->list_start%l->maxsize]);
				free(l->list[l->list_start%l->maxsize]);
				l->list_start++; l->list_size--;
			}
		}
		del_from_htab(l, l->list[l->list_start%l->maxsize]);
		free(l->list[l->list_start%l->maxsize]);
		l->list_start++; l->list_size--;
		size_t end = (l->list_start+l->list_size)%l->maxsize;
		l->list[end] = it;
		INFO2("add_item() %s circular list %s full.\n",l->hash(item),l->list_name);
		l->list_size++;
	} else {
		free(it);
		WARN("add_item() %s list %s full.\n", l->hash(item),l->list_name);
		return NULL;
	}
	add_item_to_htab(l, it);
	//dump_hashtable(l->htab);
	return NULL;
}

int del_item(list_t *l, const void* item) {
	if (l->hash == NULL) return -1;
	size_t i,posn;
	for (posn=l->list_start; posn<l->list_start+l->list_size; posn++) {
		if ((l->cmp(l->hash,l->list[posn%l->maxsize],item))) {
				break; //found a match
		}
	}
	if (posn==l->list_start+l->list_size) {
		INFO2("del_item() %s item not found.\n", l->hash(item));
		return -1;
	}
	del_from_htab(l,item);  //need to do this before do free
	free(l->list[posn%l->maxsize]);
	for (i=posn; i<l->list_start+l->list_size-1; i++) {
		l->list[i%l->maxsize] = l->list[(i+1)%l->maxsize];
	}
	l->list_size--;
	//dump_hashtable(l->htab);
	return 0;
}

size_t get_list_size(list_t *l) {
	return l->list_size;
}

void* get_list_item(list_t *l, size_t row) {
	return l->list[(l->list_start+row)%l->maxsize];
}

void sort_list(list_t *l, int (*sort_cmp)(const void *, const void *)) {
	if (l->list_start != 0) return; // to do
	if (!sort_cmp) return;
	qsort(l->list,l->list_size,sizeof(void*),sort_cmp);
}

#define FILE_VERSION 1
void save_list(list_t *l, char* path, size_t item_size) {
	FILE *fp = fopen(path,"w");
	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", path, strerror(errno));
		return;
	}
	uint8_t ver = FILE_VERSION;
	size_t res = fwrite(&ver,1,1,fp);
	if (res<1) {
		WARN("Problem saving version to %s: %s\n",path,strerror(errno));
		return;
	}
	res = fwrite(&l->list_size,sizeof(l->list_size),1,fp);
	if (res<1) {
		WARN("Problem saving size to %s: %s\n",path,strerror(errno));
		return;
	}
	for(size_t i = l->list_start; i < l->list_start+l->list_size; i++){
		int res=(int)fwrite(l->list[i%l->maxsize],item_size,1,fp);
		if (res<1) {
			WARN("Problem saving %s: %s\n", path, strerror(errno));
			break;
		}
	}
	fclose(fp);
}

void load_list(list_t *l, char* path, size_t item_size) {
	
	// initialise hash table
	if (l->htab!=NULL) hashtable_free(l->htab);
	l->list_size = 0; l->list_start=0; l->maxsize=MAXLIST;
	l->htab = hashtable_new(l->maxsize);
	//return;

	// open and read file
	#define STR_SIZE 1024
	FILE *fp = fopen(path,"r");
	if (fp==NULL) {
		WARN("Problem opening %s for reading: %s\n", path, strerror(errno));
		return;
	}
	uint8_t ver;
	size_t res = fread(&ver,1,1,fp);
	if (res<1) {
		WARN("Problem loading %s: %s", path, strerror(errno));
		return;
	}
	if (ver != FILE_VERSION) {
	WARN("Problem loading %s: version mismatch, expected %d got %d", path, FILE_VERSION, ver);
		return;
	}
	res=fread(&l->list_size,sizeof(l->list_size),1,fp);
	if (res<1) {
		WARN("Problem loading %s: %s", path, strerror(errno));
		return;
	}
	if (l->list_size < 0) {
		WARN("Problem loading %s: list_size %zu <0\n",path,l->list_size);
		l->list_size=0;
		return;
	}
	if (l->list_size > l->maxsize) {
		WARN("Problem loading %s: list_size %zu too large\n",path,l->list_size);
		l->list_size=0;
		return;
	}
	size_t i;
	for(i = 0; i < l->list_size; i++){
		l->list[i] = malloc(item_size);
		res=fread(l->list[i],item_size,1,fp);
		if (res<1) {
			WARN("Problem loading %s: %s", path, strerror(errno));
			free(l->list[i]);
			l->list_size=0;
			break;
		}
		// and put pointer into hash table
		add_item_to_htab(l,l->list[i]);
	}
	if (i<l->list_size) {
		WARN("Read too few records from %s: expected %zu, got %zu\n",path,l->list_size,i);
		l->list_size = 0;
	}
	fclose(fp);
}

