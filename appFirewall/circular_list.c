//
//  circular_list.c
//  appFirewall
//

#include "circular_list.h"

void init_list(list_t *l, char* (*hash)(const void* item), int (*cmp)(const void* item1, const void* item2), int circular, char* name) {
	l->hash = hash;
	l->cmp = cmp;
	l->circular = circular;
	l->htab = hashtable_new(MAXLIST);
	l->list_size=0; l->list_start=0;
	for (int i=0; i<MAXLIST;i++) l->list[i]=NULL;
	strlcpy(l->list_name,name,BUFSIZE);
}

void free_list(list_t *l) {
	for (int i=l->list_start; i<l->list_start+l->list_size;i++) {
		if (l->list[i%MAXLIST]) {
			free(l->list[i%MAXLIST]);
			l->list[i%MAXLIST]=NULL;
		}
	}
	if (l->htab!=NULL) hashtable_free(l->htab);
	l->list_size=0; l->list_start=0;
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

int find_item_row(list_t *l, const void* item) {
	if (l->hash == NULL) return -1;
	int posn;
	for (posn=l->list_start; posn<l->list_start+l->list_size; posn++) {
		if ((l->cmp(l->list[posn%MAXLIST],item))) {
				break; //found a match
		}
	}
	return posn;
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

void add_item(list_t *l, void* item, int item_size) {
	if (l->hash == NULL) return;
	if (in_list(l, item, 0)) {
		INFO("add_item() item %s exists.\n", l->hash(item));
		return;
	}

	void* it = malloc(item_size);
	memcpy(it,item,item_size); // we take a copy
	if (l->list_size < MAXLIST) {
		int end = (l->list_start+l->list_size)%MAXLIST;
		l->list[end] = it;
		l->list_size++;
	} else if (l->circular){
		del_from_htab(l, l->list[l->list_start%MAXLIST]);
		l->list_start++; l->list_size--;
		int end = (l->list_start+l->list_size)%MAXLIST;
		l->list[end] = it;
		l->list_size++;
	} else {
		free(it);
		WARN("add_item() %s list %s full.\n", l->hash(item),l->list_name);
		return;
	}
	add_item_to_htab(l, it);
	//dump_hashtable(l->htab);
}

int del_item(list_t *l, const void* item) {
	if (l->hash == NULL) return -1;
	int i,posn;
	for (posn=l->list_start; posn<l->list_start+l->list_size; posn++) {
		if ((l->cmp(l->list[posn%MAXLIST],item))) {
				break; //found a match
		}
	}
	if (posn==l->list_start+l->list_size) {
		INFO("del_item() %s item not found.\n", l->hash(item));
		return -1;
	}
	del_from_htab(l,item);  //need to do this before do free
	free(l->list[posn%MAXLIST]);
	for (i=posn; i<l->list_start+l->list_size-1; i++) {
		l->list[i%MAXLIST] = l->list[(i+1)%MAXLIST];
	}
	l->list_size--;
	//dump_hashtable(l->htab);
	return 0;
}

int get_list_size(list_t *l) {
	return l->list_size;
}

void* get_list_item(list_t *l, int row) {
	return l->list[(l->list_start+row)%MAXLIST];
}

void sort_list(list_t *l, int (*sort_cmp)(const void *, const void *)) {
	if (l->list_start != 0) return; // to do
	if (!sort_cmp) return;
	qsort(l->list,l->list_size,sizeof(void*),sort_cmp);
}

void save_list(list_t *l, char* path, int item_size) {
	//printf("saving block_list\n");
	#define STR_SIZE 1024
	FILE *fp = fopen(path,"w");

	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", path, strerror(errno));
		return;
	}
	int i;
	int res = (int)fwrite(&l->list_size,sizeof(int),1,fp);
	if (res<1) {
		WARN("Problem saving size to %s: %s\n",path,strerror(errno));
		return;
	}
	for(i = l->list_start; i < l->list_start+l->list_size; i++){
		int res=(int)fwrite(l->list[i%MAXLIST],item_size,1,fp);
		if (res<1) {
			WARN("Problem saving %s: %s\n", path, strerror(errno));
			break;
		}
	}
	fclose(fp);
}

void load_list(list_t *l, char* path, int item_size) {
	
	// initialise hash table
	if (l->htab!=NULL) hashtable_free(l->htab);
	l->htab = hashtable_new(MAXLIST);
	l->list_size = 0; l->list_start=0;
	//return;

	// open and read file
	#define STR_SIZE 1024
	FILE *fp = fopen(path,"r");
	if (fp==NULL) {
		WARN("Problem opening %s for reading: %s\n", path, strerror(errno));
		return;
	}
	int res=(int)fread(&l->list_size,sizeof(int),1,fp);
	if (res<1) {
		WARN("Problem loading %s: %s", path, strerror(errno));
		return;
	}
	if (l->list_size<0) {
		WARN("Problem loading %s: list_size %d <0\n",path,l->list_size);
		l->list_size=0;
		return;
	}
	if (l->list_size>MAXLIST) {
		WARN("Problem loading %s: list_size %d too large\n",path,l->list_size);
		l->list_size=0;
		return;
	}
	int i;
	for(i = 0; i < l->list_size; i++){
		l->list[i] = malloc(item_size);
		res=(int)fread(l->list[i],item_size,1,fp);
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
		WARN("Read too few records from %s: expected %d, got %d\n",path,l->list_size,i);
		l->list_size = 0;
	}
	fclose(fp);
}

