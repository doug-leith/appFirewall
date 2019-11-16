//
//  blocklists.c
//  appFirewall
//

#include "blocklists.h"

Hashtable *bls_htab=NULL; // hash table of pointers into black list for fast lookup
#define STR_SIZE 1024

void init_blocklists_tab() {
	// initialise hash table
	if (bls_htab!=NULL) hashtable_free(bls_htab);
	bls_htab = hashtable_new(HTABSIZE);
}

void* in_blocklists_htab(bl_item_t *b) {
	if (bls_htab!=NULL) {
		char *temp = bl_hash((void*)b);
		void* res=hashtable_get(bls_htab, temp);
		free(temp);
		return res;
	} else
		return NULL;
}

void load_blocklistfile(const char* fname) {
	// load (app,domain) pairs from a file and adds to block list table
	// (so not shown in GUI, which only displays block list itself)
	
	init_blocklists_tab();
	
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
			// check first item is not an IP address (i.e. its a host file by
			// mistake !)
			first = trimwhitespace(first);
			struct in_addr addr;
			struct in6_addr addr6;
			if (inet_pton(AF_INET,first,&addr)==1) break; // its an IPv4 address
			if (inet_pton(AF_INET6,first,&addr6)==1) break; // its an IPv6 address
			// looks ok, hopefully its an app process name
			bl_item_t b;
			strlcpy(b.name, first,BUFSIZE);
			
			// get second word, it should be the domain name
			char* domain = strtok_r(NULL, ",", &ptr);
			if (domain == NULL) continue; // no domain name, skip
			domain = trimwhitespace(domain);
			if (!strcmp(domain,"localhost")) continue;
			if (!strcmp(domain,"localhost.localdomain")) continue;
			if (!strcmp(domain,"local")) continue;
			if (!strcmp(domain,"ip6-localhost")) continue;
			if (!strcmp(domain,"ip6-loopback")) continue;
			// strip any newline
			char * nl = strstr(domain,"\n"); if (nl!=NULL) *nl=0;
			DEBUG2("%s\n", domain);
			strlcpy(b.domain, domain, BUFSIZE);

			// and add to blocklists table
			char *str = bl_hash(&b);
			hashtable_put(bls_htab, str, bls_htab); // last parameter is just a placeholder
			free(str);
			count++;
	}
	fclose(fp);
	INFO("loaded %d entries\n",count);
	if (line) free(line);
	
}
