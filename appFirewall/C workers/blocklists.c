//
//  blocklists.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//
#include "blocklists.h"

// to allow a crude sort of wildcard we maintain three tables.
// 1. bls_app_htab blocks apps based on their name
// 2. wls_app_htab passes (app name,domain) pairs, so
// combined with bls_app_htab we can allow only selected
// connections by an app i.e. by default an app cannot make
// connections unless otherwise specified.
// 3. bls_htab blocks based on (app name,domain) pairs, so if
// an app is only on this list then by default it can make
// connections unless otherwise specified
static Hashtable *bls_htab=NULL; // black list based on (app name,domain) pairs
static Hashtable *bls_app_htab=NULL; // black list based on app name only
static Hashtable *wls_app_htab=NULL; // whitelist based on (app name,domain) pairs
static pthread_mutex_t bls_mutex = MUTEX_INITIALIZER;

void init_blocklists_tabs() {
	// initialise hash table
	// must hold lock when call
	// - only called by load() below
	if (bls_htab!=NULL) hashtable_free(bls_htab);
	bls_htab = hashtable_new(HTABSIZE);

	if (bls_app_htab!=NULL) hashtable_free(bls_app_htab);
	bls_app_htab = hashtable_new(HTABSIZE);

	if (wls_app_htab!=NULL) hashtable_free(wls_app_htab);
	wls_app_htab = hashtable_new(HTABSIZE);
}

char* bls_app_hash(const void *it) {
	// generate table lookup key for bls_app_htab
	bl_item_t *item = (bl_item_t*) it;
	size_t len = strnlen(item->name,MAXCOMLEN)+2;
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	return temp;
}

void* in_blocklists_htab(bl_item_t *b) {
	// return values are just NULL or non-NULL, actual values
	// don't matter
	TAKE_LOCK(&bls_mutex,"in_blocklists_htab()");
	if (wls_app_htab!=NULL) {
		char *temp = cl_hash((void*)b);
		void* res_ptr=hashtable_get(wls_app_htab, temp);
		free(temp);
		// on whitelist, pass
		if (res_ptr != NULL) {
			pthread_mutex_unlock(&bls_mutex);
			return NULL;
		}
	}
	if (bls_app_htab!=NULL) {
		char *temp = bls_app_hash((void*)b);
		void* res_ptr=hashtable_get(bls_app_htab, temp);
		free(temp);
		// on blacklist, block
		if (res_ptr != NULL) {
			pthread_mutex_unlock(&bls_mutex);
			return res_ptr;
		}
	}
	if (bls_htab!=NULL) {
		char *temp = cl_hash((void*)b);
		void* res_ptr=hashtable_get(bls_htab, temp);
		free(temp);
		// on blacklist, block
		if (res_ptr != NULL) {
			pthread_mutex_unlock(&bls_mutex);
			return res_ptr;
		}
	}
	pthread_mutex_unlock(&bls_mutex);
	// not on any list, pass
	return NULL;
}

int_sw load_blocklistfile(const char* fname) {
	// load (app,domain) pairs from a file and adds to block list table
	// (so not shown in GUI, which only displays block list itself)
	
	//printf("load block list file()\n");
	FILE *  fp = fopen(fname, "r");
	if (fp == NULL) {
			WARN("Problem opening block list file %s for reading: %s\n", fname, strerror(errno));
			return -1;
	}
	TAKE_LOCK(&bls_mutex,"load_blocklistfile()");
	init_blocklists_tabs();
	pthread_mutex_unlock(&bls_mutex);
	char * line = NULL;
	size_t len = 0; int count=0;
	int allapps=0; bl_item_t b;
	ssize_t read;
	while ((read = getline(&line, &len, fp)) != -1) {
		//printf("%s", line);
		// split line using comma as delimiter
		char* ptr;
		char* first = strtok_r(line, ",", &ptr);
		if (first == NULL) continue; // blank line
		if (first[0] == '#') continue; // comment line
		// check first item is not an IP address (i.e. its a
		// host file by mistake !)
		first = trimwhitespace(first);
		struct in_addr addr;
		struct in6_addr addr6;
		if (inet_pton(AF_INET,first,&addr)==1) break; // its an IPv4 address
		if (inet_pton(AF_INET6,first,&addr6)==1) break; // its an IPv6 address
		if (strcmp(first,"*")==0) {
			// its a domain that's blocked for all apps
			allapps=1;
		} else {
			// looks ok, hopefully its an app process name
			strlcpy(b.name,first,MAXCOMLEN);
			allapps=0;
		}
		
		// get second word,
		char* second = strtok_r(NULL, ",", &ptr);
		if (second == NULL) continue; // no domain name, skip
		second = trimwhitespace(second);
		// strip any newline
		char * nl = strstr(second,"\n"); if (nl!=NULL) *nl=0;
		DEBUG2("%s\n", second);
		
		// if blocking all connections its a "*"
		if (strcmp(second,"*")==0) {
			if (!allapps) {
				// add to app blacklist
				char *str = bls_app_hash(&b);
				TAKE_LOCK(&bls_mutex,"load_blocklistfile() #2");
				hashtable_put(bls_app_htab, str, bls_htab); // last parameter is just a placeholder
				pthread_mutex_unlock(&bls_mutex);
				free(str);
				count++;
				//printf("app blacklist: %s\n",b.name);
			}
			continue;
		}
		// if first character is a "-" we're adding
		// (name,domain) pair to whitelist, else to blacklist
		Hashtable *htab=NULL;
		char domain[MAXDOMAINLEN];
		if (second[0]=='-') {
			htab = wls_app_htab;
			strlcpy(domain,&second[1],MAXDOMAINLEN);
		} else {
			htab = bls_htab;
			strlcpy(domain,&second[0],MAXDOMAINLEN);
		}
		// rest should be the domain name
		if (!strcmp(domain,"localhost")) continue;
		if (!strcmp(domain,"localhost.localdomain")) continue;
		if (!strcmp(domain,"local")) continue;
		if (!strcmp(domain,"ip6-localhost")) continue;
		if (!strcmp(domain,"ip6-loopback")) continue;
		strlcpy(b.domain, domain, MAXDOMAINLEN);
		
		if (!allapps){
			// and add to blocklists table
			char *str = cl_hash(&b);
			TAKE_LOCK(&bls_mutex,"load_blocklistfile() #3");
			hashtable_put(htab, str, bls_htab); // last parameter is just a placeholder
			pthread_mutex_unlock(&bls_mutex);
			free(str);
			count++;
			//printf("list: %s,%s %d\n",b.name,domain,second[0]=='-');
		} else { // applies to all apps
			// add to host lists table
			add_hostlist(domain);
			//printf("domain blacklist: %s\n",domain);
			count++;
		}
	}
	fclose(fp);
	INFO("loaded %d entries\n",count);
	if (line) free(line);
	return 0;
}
