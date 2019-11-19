//
//  blocklists.c
//  appFirewall
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
Hashtable *bls_htab=NULL; // black list based on (app name,domain) pairs
Hashtable *bls_app_htab=NULL; // black list based on app name only
Hashtable *wls_app_htab=NULL; // whitelist based on (app name,domain) pairs
#define STR_SIZE 1024

void init_blocklists_tabs() {
	// initialise hash table
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
	int len = (int)(strlen(item->name)+2);
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	return temp;
}

void* in_blocklists_htab(bl_item_t *b) {
	if (wls_app_htab!=NULL) {
		char *temp = bl_hash((void*)b);
		void* res=hashtable_get(wls_app_htab, temp);
		free(temp);
		// on whitelist, pass
		if (res != NULL) return NULL;
	}
	if (bls_app_htab!=NULL) {
		char *temp = bls_app_hash((void*)b);
		void* res=hashtable_get(bls_app_htab, temp);
		free(temp);
		// on blacklist, block
		if (res != NULL) return res;
	}
	if (bls_htab!=NULL) {
		char *temp = bl_hash((void*)b);
		void* res=hashtable_get(bls_htab, temp);
		free(temp);
		// on blacklist, block
		if (res != NULL) return res;
	}
	// not on any list, pass
	return NULL;
}

void load_blocklistfile(const char* fname) {
	// load (app,domain) pairs from a file and adds to block list table
	// (so not shown in GUI, which only displays block list itself)
	
	init_blocklists_tabs();
	
	//printf("load block list file()\n");
	FILE *  fp = fopen(fname, "r");
	if (fp == NULL) {
			WARN("Problem opening block list file %s for reading: %s\n", fname, strerror(errno));
			return;
	}

	char * line = NULL;
	size_t len = 0; int count=0;
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
			// looks ok, hopefully its an app process name
			bl_item_t b;
			strlcpy(b.name,first,BUFSIZE);
			
			// get second word,
			char* second = strtok_r(NULL, ",", &ptr);
			if (second == NULL) continue; // no domain name, skip
			second = trimwhitespace(second);
			// strip any newline
			char * nl = strstr(second,"\n"); if (nl!=NULL) *nl=0;
			DEBUG2("%s\n", second);
			
			// if blocking all connections its a "*"
			if (strcmp(second,"*")==0) {
				// add to app blacklist
				char *str = bls_app_hash(&b);
				hashtable_put(bls_app_htab, str, bls_htab); // last parameter is just a placeholder
				free(str);
				count++;
				continue;
			}
			// if first character is a "-" we're adding
			// (name,domain) pair to whitelist, else to blacklist
			Hashtable *htab=NULL;
			char domain[BUFSIZE];
			if (second[0]=='-') {
				htab = wls_app_htab;
				strlcpy(domain,&second[1],BUFSIZE);
			} else {
				htab = bls_htab;
				strlcpy(domain,&second[0],BUFSIZE);
			}
			// rest should be the domain name
			if (!strcmp(domain,"localhost")) continue;
			if (!strcmp(domain,"localhost.localdomain")) continue;
			if (!strcmp(domain,"local")) continue;
			if (!strcmp(domain,"ip6-localhost")) continue;
			if (!strcmp(domain,"ip6-loopback")) continue;
			strlcpy(b.domain, domain, BUFSIZE);

			// and add to blocklists table
			char *str = bl_hash(&b);
			hashtable_put(htab, str, bls_htab); // last parameter is just a placeholder
			free(str);
			count++;
	}
	fclose(fp);
	INFO("loaded %d entries\n",count);
	if (line) free(line);
	
}
