//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "dns_sniffer.h"

// circular list of reverse DNS lookups based on sniffed DNS reply packets
static list_t dns_cache = LIST_INITIALISER;
// need lock because called both by main sniffer_blocker thread and by waiting
// list thread
static pthread_mutex_t dns_mutex = MUTEX_INITIALIZER;

// DNS header struct
struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

//-------------------------------------------------------

char* dns_hash(const void* it) {
	dns_item_t *item = (dns_item_t*)it;
	char* temp = malloc(INET6_ADDRSTRLEN);
	inet_ntop(item->af,&item->addr,temp,INET6_ADDRSTRLEN);
	return temp;
}

dns_count_t* get_dns_count(int af, struct in6_addr addr) {
	// get a count for each domain name that associated with IP
	dns_item_t d;
	d.af=af;
	memcpy(&d.addr,&addr,sizeof(struct in6_addr));
	TAKE_LOCK(&dns_mutex,"get_dns_count()");
	dns_item_t* it = in_list(&dns_cache,&d,0);
	if (it == NULL) {
		pthread_mutex_unlock(&dns_mutex);
		return NULL;
	}
	dns_count_t* c = malloc(sizeof(dns_count_t));
	memset(c,0,sizeof(dns_count_t));
	c->num=0;
	//printf("%d:",it->list_size);
	for (size_t i=0; i<it->list_size; i++) {
		size_t index = (it->list_start+i)%MAXDNS;
		//printf("%s ",it->names[index]);
		int found = 0; size_t j;
		for (j = 0; j< c->num; j++) {
			if (strcmp(c->name[j],it->names[index])==0) {
				found = 1; break;
			}
		}
		if (found) {
			c->count[j]++;
		} else {
			strlcpy(c->name[c->num], it->names[index], MAXDOMAINLEN);
			c->count[c->num] = 1;
			c->num++;
		}
	}
	//printf("num=%d\n",c->num);
	pthread_mutex_unlock(&dns_mutex);
	return c;
}

static char res[(MAXDOMAINLEN+32)*MAXDNS+2];
char* get_dns_count_str(int af, struct in6_addr addr){
	dns_count_t* c = get_dns_count(af,addr);
	memset(res,0,sizeof(res));
	if (c == NULL) return res;
	for (size_t j = 0; j< c->num; j++) {
		char temp[MAXDOMAINLEN+32];
		snprintf(temp,MAXDOMAINLEN+32, "%s(%zu) ", c->name[j], c->count[j]);
		strlcat(res,temp,sizeof(res));
	}
	free(c);
	return res;
}

void dump_dns_cache() {
	list_t *l = &dns_cache;
	printf("dns_cache start/size: %zu/%zu\n", l->list_start, l->list_size);
	for (size_t i=0; i<get_list_size(l); i++) {
		dns_item_t *b = get_list_item(l,i);
		char addr_name[INET6_ADDRSTRLEN];
		inet_ntop(b->af,&b->addr,addr_name,INET6_ADDRSTRLEN);
		printf("%s: ",addr_name);
		dns_count_t* c = get_dns_count(b->af, b->addr);
		for (size_t j = 0; j< c->num; j++) {
			printf("%s(%zu) ", c->name[j], c->count[j]);
		}
		printf("\n");
	}
}

char* lookup_dns_name(int af, struct in6_addr addr) {
	dns_item_t d;
	d.af=af;
	memcpy(&d.addr,&addr,sizeof(struct in6_addr));
	TAKE_LOCK(&dns_mutex,"lookup_dns_name()");
	dns_item_t* res_ptr = in_list(&dns_cache,&d,0);
	if (res_ptr != NULL) {
		//printf("found '%s' for %s/'%s'\n",res.name, dns_hash(&d), dns_hash(&res));
		char *name = malloc(MAXDOMAINLEN);
		strlcpy(name,res_ptr->name,MAXDOMAINLEN);
		pthread_mutex_unlock(&dns_mutex);
		return name;
	} else {
		//printf("not found %s\n",dns_hash(&d));
		pthread_mutex_unlock(&dns_mutex);
		return NULL;
	}
}

//static FILE* dns_fp=NULL;
void append_dns(int af, struct in6_addr addr, char* name) {
	dns_item_t d;
	d.af=af;
	memcpy(&d.addr,&addr,sizeof(struct in6_addr));
	strlcpy(d.name,name,MAXDOMAINLEN);
	d.list_start = 0; d.list_size = 1;
	strlcpy(d.names[0],name,MAXDOMAINLEN);
	
	TAKE_LOCK(&dns_mutex,"append_dns()");
	dns_item_t* it = in_list(&dns_cache, &d, 0);
	if (it == NULL) {
		// a new domain, add initial entry to list
		add_item(&dns_cache,&d,sizeof(dns_item_t));
		pthread_mutex_unlock(&dns_mutex);
		printf("adding new domain %s\n",name);
		return;
	}
	
	// dns entry already exists, we keep a list of
	// domain names associated with this IP address.
	// duplicates are ok as they give an idea of the
	// domain which occurs most frequently
	if (it->list_size == MAXDNS) {
		// wrap circular list
		it->list_start++; it->list_size--;
	}
	strlcpy(it->names[(it->list_start+it->list_size)%MAXDNS],name,MAXDOMAINLEN);
	it->list_size++;
	// and we keep a copy of the most recent domain associated with this
	// IP, we use this to resolve lookups
	strlcpy(it->name,name,MAXDOMAINLEN);
	pthread_mutex_unlock(&dns_mutex);
	//printf("appending domain %s: %s\n",name, get_dns_count_str(af,addr));
	
	/*if (dns_fp == NULL) {
		char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
		strlcat(path,"dns_log.txt",STR_SIZE);
		dns_fp = fopen (path,"a");
	}
	char addr_name[INET6_ADDRSTRLEN];
	inet_ntop(af,&addr,addr_name,INET6_ADDRSTRLEN);
	fprintf(dns_fp,"%s %s exists (%s)\n", d.name, addr_name, prev->name);*/
}

void save_dns_cache(const char* fname) {
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&dns_mutex,"save_dns_cache()");
	save_list(&dns_cache,path,sizeof(dns_item_t), DNS_FILE_VERSION);
	pthread_mutex_unlock(&dns_mutex);
}

void load_dns_cache(const char* fname) {
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&dns_mutex,"load_dns_cache()");
	init_list(&dns_cache,dns_hash,NULL,1,DNS_CACHE_SIZE,"dns_cache");
	load_list(&dns_cache,path,sizeof(dns_item_t),DNS_FILE_VERSION);
	pthread_mutex_unlock(&dns_mutex);
}

//-------------------------------------------------------
/*#include <Foundation/Foundation.h>

void* reverse_dns_lookup_thread(void*ptr) {
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ptr;
	char dn[INET6_ADDRSTRLEN];
	inet_ntop(sa->sin6_family,&sa->sin6_addr, dn, INET6_ADDRSTRLEN);
	//char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	//int res = getnameinfo((struct sockaddr *)sa, sizeof(struct sockaddr_in6), hbuf, //sizeof(hbuf), sbuf, sizeof(sbuf), NI_NAMEREQD);
	//if (res!=0) {
	//	if (res!=EAI_NONAME)
	//		WARN("Problem doing reverse DNS lookup for %s: %s", dn, gai_strerror(res));
	//	else
	//		INFO2("Reverse DNS failed for %s\n",dn);
	//} else {
	//	//append_dns(sa->sin6_family,sa->sin6_addr,hbuf);
	//	INFO2("Reverse DNS found: %s -> %s\n",dn,hbuf);
	//}

	// NSHost seems to resolve a good many more addresses than getnameinfo().  Mhy guess is
	// that in MAC  OS getnameinfo() just uses the local dns cache ?
	NSString *name = [[NSHost hostWithAddress:[NSString stringWithUTF8String:dn]] name];
	const char* str = [name UTF8String];
	if (str) {
		append_dns(sa->sin6_family,sa->sin6_addr,(char*)str);
		INFO2("Reverse DNS found using NSHost: %s -> %s\n",dn,str);
	} else {
		INFO2("Reverse DNS using NSHost failed for %s\n",dn);
	}

	free(sa);
	return NULL;
}

void reverse_dns_lookup(int af, struct in6_addr addr) {
	pthread_t thread;
	struct sockaddr_in6 *sa=malloc(sizeof(struct sockaddr_in6));
	sa->sin6_family = (sa_family_t)af;
	sa->sin6_addr = addr;
	pthread_create(&thread, NULL, reverse_dns_lookup_thread, sa);
}
*/

void reverse_dns_lookup(int af, struct in6_addr addr) {
	// just a stub.  not sure we should be doing reverse DNS within firewall
	// as it means firewall itself generates network traffic that can potentially
	// reveal app activity.
	return;
}


static u_char *dns_label_to_str(u_char **label, u_char *dest,
                               size_t dest_size,
                               const u_char *payload,
                               const u_char *end) {
	u_char *tmp, *dst = dest;

	if (!label || !*label || (*label>end) || !dest) goto err;

	*dest = '\0';
	while (*label < end && **label) {
		if (**label & 0xc0) { /* Pointer */
			tmp = (u_char *)payload;
			tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
			/*printf("ptr size=%d, offset %u\n",*tmp, ntohs(*(uint16_t *)(*label)) & 0x3fff);
			for (int j = 0; j< tmp-payload+8; j++) {
				//printf("%u ", *(payload+j));
			}
			printf("\n");*/
			while (tmp < end && *tmp) {
				if (*tmp & 0xc0) {
					// pointer
					u_char* ptr = (u_char *)payload;
					ptr += ntohs(*(uint16_t *)tmp) & 0x3fff;
					if (ptr >= end) {
						/*printf("second ptr>end, offset %u\n", ntohs(*(uint16_t *)tmp) & 0x3fff);
						for (int j = 0; j< tmp-payload+8; j++) {
							printf("%u ", *(payload+j));
						}
						printf("\n");*/
						DEBUG2("Label pointer points outside packet in dns_label_to_str(), likely DNS snaplen too short and packet has been truncated\n");
						goto err;
					}
					if (dst + *ptr >= dest + dest_size) { // shouldn't happen
						ERR("Label (from pointer) is too large for our buffer in dns_label_to_str() (our buffer size %zu, label needs %ld more)\n", dest_size, (dst + *ptr)-(dest + dest_size) );
				  	goto err;
					}
					memcpy(dst, ptr+1, *ptr);
					dst += *ptr;
					*dst = '.'; dst++;
					break; // end with ptr
				} else {
					// label
				  if (dst + *tmp >= dest + dest_size) { // shouldn't happen
						ERR("Label is too large for our buffer in dns_label_to_str() (our buffer size %zu, label needs %ld more)\n", dest_size, (dst + *tmp)-(dest + dest_size) );
				  	goto err;
					}
				  memcpy(dst, tmp+1, *tmp);
				  dst += *tmp; tmp += *tmp + 1;
				  if (dst+1 >= dest + dest_size) { // shouldn't happen
						ERR("Label has run off end of our buffer in dns_label_to_str() (our buffer size %zu, label needs %ld more)\n", dest_size, dst+1-(dest + dest_size) );
				  	goto err;
					}
					*dst = '.'; dst++;
				}
			};
			*label += 2;
		} else { /* Label */
			//printf("label ");
			if ((*label + **label) >= end) {
				DEBUG2("Label overflows packet in dns_label_to_str(), likely DNS snaplen too short and packet has been truncated\n");
				goto err;
			}
			if (**label + dst >= dest + dest_size) { // shouldn't happen
				ERR("Label (no pointer) is too large for our buffer in dns_label_to_str() (our buffer size %zu, label needs %ld more)\n", dest_size, (**label + dst)-(dest + dest_size) );
				goto err;
			}
			/*printf("name len %d ", **label);
			int i;
			for (i=1; i<=**label; i++) {
				printf("%02x ", (*label)[i]);
			}
			printf("\n");*/
			memcpy(dst, *label + 1, **label);
			dst += **label;
			if (dst+1 >= dest + dest_size) {
				ERR("Label (no pointer) has run off end of our buffer in dns_label_to_str() (our buffer size %zu, label needs %ld more)\n", dest_size, dst+1-(dest + dest_size) );
				goto err;
			}
			*label += **label + 1;
			*dst = '.'; dst++;
		}
	}

	*(--dst) = '\0';
	return dest;
err:
	if (dest) *dest = '\0';
	return dest;
}

//-------------------------------------------------------
static u_char *skip_dns_label(u_char *label, const u_char * end){
	u_char *tmp;

	if (!label || (label>end)) return NULL;
	
	int label_last=1;
	while (*label) {
		// a pointer
		if (*label & 0xc0) {
			label = label + 2; // pointer is 2 bytes long
			label_last=0;
		} else {
			tmp = label + *label + 1; // first byte gives length of label
			label = tmp;
			label_last=1;
		}
	}
	if (label + label_last >= end)
		return NULL;
	else
		return label + label_last;
}

void parse_RR(u_char* t, u_char* label, const u_char* payload, const u_char* end) {
	/* Get the data field length */
	u_char buf[BUFSIZE];
	u_char *tmp = t;
	u_char* l = label;
	if (!t || (t>=end) || (l>=end)) goto err;
	if (l==NULL) {
		l = dns_label_to_str(&tmp, buf, BUFSIZE, payload, end);
	}
	if ((l==NULL) || (strnlen((char*)l,BUFSIZE)==0)) {
		// likely a truncated pkt (snaplen too short)
		WARN("Empty label '%s' in parse_RR()\n", l);
		/*for (int i =0; i< tmp-t+16; i++) {
			printf("%u ", *(t+i));
		}
		printf("\n");*/
		return;
	}
	tmp = skip_dns_label(t, end);
	// debugging: dump out raw bytes ...
	/*printf("RR bytes:");
	for (int j =0; j<tmp-t+2; j++) {
		//printf("%u ", *(t+j));
	}
	//printf("\n");*/
	
	if ((tmp==NULL) || (tmp+10>end)) goto err; // shouldn't happen
	uint16_t qtype = ntohs(*(uint16_t *)tmp);
	tmp+=10;
	struct in6_addr addr; memset(&addr,0,sizeof(addr));
	int af=0;
	if(qtype==1) {// A
			if (tmp+sizeof(struct in_addr)>end) goto err; // shouldn't happen
			memcpy(&addr,tmp,sizeof(struct in_addr));
			af=AF_INET;
			if (!addr.s6_addr) return; // 0.0.0.0
	} else if (qtype==28) { // AAAA
			if (tmp+sizeof(struct in6_addr)>end) goto err; // shouldn't happen
			memcpy(&addr,tmp,sizeof(struct in6_addr));
			af=AF_INET6;
		if (!addr.s6_addr) return; // ::
	} else {
		return;
	}
	append_dns(af,addr,(char*)l);
	char n[INET6_ADDRSTRLEN];
	inet_ntop(af, &addr, n, INET6_ADDRSTRLEN);
	INFO2("DNS %d %s %s\n",af,l,n);
	return;
err:
	DEBUG2("Truncated RR found in parse_RR()\n");
 	return;
}

u_char* parse_RRs(u_char** posn, const u_char* end, uint16_t qtype, int n) {
	u_char* tmp = *posn;
	if (!tmp) return NULL; // shouldn't happen
	
	u_char* RR = NULL;	
	u_char* t = tmp, *last_t;
	for (int i=0;i< n; i++) {
		if (tmp > end) goto err;
		last_t = t; t = tmp;
		tmp = skip_dns_label(tmp, end);
		if (!tmp || (tmp + 10 > end)) goto err;
		// Get the type, and skip class and ttl
		uint16_t len = ntohs(*(uint16_t *)tmp);
		// debugging check
		if ((tmp < t+1) && (len != 41)) {
			// empty label, shouldn't happen except for OPT records (type 41)
			ERR("Empty label in parse_RRs(). i=%d, len=%d, prev:",i,len );
			for (int j = 0; j< tmp-last_t+8; j++) {
				if (last_t+j == t) printf("\ncurr:");
				printf("%u ", *(last_t+j));
			}
			printf("\n");
			return NULL;
		}
		//printf("i=%d, len=%d, tmp-t=%ld\n",i,len,tmp-t);
		/*// debugging: dump out raw bytes ...
		//printf("qtype=%d/%d, i=%d: ",len, qtype,i);
		for (int j =0; j<tmp-t+2; j++) {
			//printf("%u ", *(t+j));
		}
		//printf("\n");*/
		tmp += 8;
		if (qtype>0) { // we have a question section, so not mDNS
			if (len == qtype) RR = t;
		} else {
			// mDNS responses don't have a question section, so let's grab any IPv4 or IPv6
			// responses.
			if (len == 1 || len == 28) { RR=t; }
		}

		/* Skip ahead to the next answer */
		if (tmp+1>end) goto err;
		tmp += ntohs(*(uint16_t *)tmp) + 2;
	}
	*posn = tmp; // advance past records
	return RR;
err:
	DEBUG2("Truncated RR found in parse_RRs()\n");
 	return NULL;
}

int dns_sniffer(const u_char* udph, size_t pkt_len) {
	// we sniff DNS response packets and save the answers so we can do
	// a rough sort of reverse lookup

	struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)udph;
	const u_char* dnsh = udph  + LIBNET_UDP_H;
	struct dnshdr* dns = (struct dnshdr*)(dnsh);
	if (dnsh + sizeof(struct dnshdr) >= udph+pkt_len) return -1; // pkt too short
	int an = ntohs(dns->ancount);
	int qd = ntohs(dns->qdcount);
	int ns= ntohs(dns->nscount);
	int ar = ntohs(dns->arcount);
	uint16_t sport=ntohs(udp->uh_sport);
	int mDNS = (sport == 5353);
	uint16_t len = ntohs(udp->uh_ulen)-LIBNET_UDP_H;
	if (!mDNS)
		stats.dns_count++;
	else
		stats.mdns_count++;
	if (len > pkt_len-LIBNET_IPV4_H-LIBNET_UDP_H) {
		//WARN("dns_sniffer() snaplen looks too short: %d/%lu\n", ntohs(udp->uh_ulen), 	pkt_len-LIBNET_IPV4_H);
		if (!mDNS) {
			stats.dns_snaplen_misses++;
			cm_add_sample_lock(&stats.cm_dns_snaplen,len-(pkt_len-LIBNET_IPV4_H-LIBNET_UDP_H));
		} else {
			stats.mdns_snaplen_misses++;
			cm_add_sample_lock(&stats.cm_mdns_snaplen,len-(pkt_len-LIBNET_IPV4_H-LIBNET_UDP_H));
		}
		// we proceed, but bearing in mind pkt might be truncated
	}
	const u_char* payload = udph+LIBNET_UDP_H; // includes DNS header
	const u_char *end = udph + pkt_len;
	if (end > payload+len) end=payload+len;
	//printf("DNS flags=%d/%d qd=%d an=%d, len=%d, sport=%d\n", dns->flags, dns->flags&0x80, qd, an, len, sport);
	if ((dns->flags&0x80)==0) return 0; // DNS query, we only want responses.
	if (!an) return 1; // response is empty, probably responding with an error
	
	/* Parse the Question section */
	u_char *tmp, *label=NULL, buf[BUFSIZE];
	uint16_t qtype = 0;

	tmp = (u_char *)payload+LIBNET_UDP_DNSV4_H; // step past the DNS header to get the question section
	if (tmp>=end) return -1; // we've already checked for this, but no harm in checking again
	int i;
	for (i=0;i<qd;i++) {
		/* Get the first question's label and question type */
		if (!qtype) {
			label = dns_label_to_str(&tmp, buf, BUFSIZE, payload, end);
			if (!label || (strnlen((char*)label,BUFSIZE)==0)) return -1;
			tmp++; if (tmp+1>=end) return -1;
			qtype = ntohs(*(uint16_t *)tmp);
			//printf("%d %s\n", qtype,label);
		} else {
			if (*tmp & 0xc0)
				tmp += 2;
			else {
				tmp = skip_dns_label(tmp, end);
				if (!tmp || (tmp>=end)) return -1;
			}
		}

		/* Skip type and class */
		tmp += 4; if (tmp >= end) return -1;
	}
	
	if (mDNS) {
		qtype = 0; // no question for mDNS
		label = NULL;
	} else if (!qtype)
		return -1; // not mDNS and no question
	//printf("qtype %d, an %d\n", qtype, an);

	// find any answering records, or for mDNS any IPv4 or IPv6 records
	u_char* RR = parse_RRs(&tmp, end, qtype, an);
	if (RR!=NULL) {
		// now parse out info from record and append to dns cache
  	parse_RR(RR, label, payload, end);
  }
	if (!mDNS) return 1;
	
	// if its mDNS, then let's also look at the additional records section
	// step past any authority section
	parse_RRs(&tmp, end, 0, ns);

	// now parse the additional records section
	RR = parse_RRs(&tmp, end, 0, ar);
	if (RR!=NULL) {
		// now parse out info from record and append to dns cache
  	parse_RR(RR, NULL, payload, end);
  }
  return 1;
}
