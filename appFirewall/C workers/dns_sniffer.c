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

static FILE* dns_fp=NULL;
void append_dns(int af, struct in6_addr addr, char* name) {
	dns_item_t d;
	d.af=af;
	memcpy(&d.addr,&addr,sizeof(struct in6_addr));
	strlcpy(d.name,name,MAXDOMAINLEN);
	//printf("adding %s/'%s'\n",d.name,dns_hash(&d));
	TAKE_LOCK(&dns_mutex,"append_dns()");
	dns_item_t *prev = add_item(&dns_cache,&d,sizeof(dns_item_t));
	pthread_mutex_unlock(&dns_mutex);
	if (prev != NULL) {
		// dns entry already exists
		if (dns_fp == NULL) {
			char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
			strlcat(path,"dns_log.txt",STR_SIZE);
			dns_fp = fopen (path,"a");
		}
		char addr_name[INET6_ADDRSTRLEN];
		inet_ntop(af,&addr,addr_name,INET6_ADDRSTRLEN);
		fprintf(dns_fp,"%s %s exists (%s)\n", d.name, addr_name, prev->name);
	}
}

void save_dns_cache(const char* fname) {
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&dns_mutex,"save_dns_cache()");
	save_list(&dns_cache,path,sizeof(dns_item_t));
	pthread_mutex_unlock(&dns_mutex);
}

void load_dns_cache(const char* fname) {
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&dns_mutex,"load_dns_cache()");
	init_list(&dns_cache,dns_hash,NULL,1,-1,"dns_cache");
	load_list(&dns_cache,path,sizeof(dns_item_t));
	pthread_mutex_unlock(&dns_mutex);
}

//-------------------------------------------------------
static u_char *dns_label_to_str(u_char **label, u_char *dest,
                               size_t dest_size,
                               const u_char *payload,
                               const u_char *end) {
	u_char *tmp, *dst = dest;

	if (!label || !*label || !dest)
		goto err;

	*dest = '\0';
	while (*label < end && **label) {
		if (**label & 0xc0) { /* Pointer */
			tmp = (u_char *)payload;
			tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
			while (tmp < end && *tmp) {
				if (dst + *tmp >= dest + dest_size)
					goto err;
				memcpy(dst, tmp+1, *tmp);
				dst += *tmp; tmp += *tmp + 1;
				if (dst > dest + dest_size) goto err;
				*dst = '.'; dst++;
			};
			*label += 2;
		} else { /* Label */
			if ((*label + **label) >= end) {
				printf("dns_label_to_str() err 1\n");
				goto err;
			}
			if (**label + dst >= dest + dest_size) {
					printf("dns_label_to_str() err 2\n");
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
			if (dst > dest + dest_size) {
				printf("dns_label_to_str() err 3\n");
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
static u_char *skip_dns_label(u_char *label){
	u_char *tmp;

	if (!label) return NULL;
	if (*label & 0xc0)
		return label + 2;

	tmp = label;
	while (*label) {
		tmp += *label + 1;
		label = tmp;
	}
	return label + 1;
}


void dns_sniffer(const struct pcap_pkthdr *pkthdr, const u_char* udph) {
	// we sniff DNS response packets and save the answers so we can do
	// a rough sort of reverse lookup

	struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)udph;
	const u_char* dnsh = udph  + LIBNET_UDP_H;
	struct dnshdr* dns = (struct dnshdr*)(dnsh);
	int an = ntohs(dns->ancount);
	int qd = ntohs(dns->qdcount);
	uint16_t len = ntohs(udp->uh_ulen)-LIBNET_UDP_H-LIBNET_UDP_DNSV4_H;
	if (len > pkthdr->caplen-LIBNET_IPV4_H-LIBNET_UDP_H-LIBNET_UDP_DNSV4_H) {
		WARN("dns_sniffer() snaplen looks too short: %d/%d", ntohs(udp->uh_ulen), 	pkthdr->caplen-LIBNET_IPV4_H);
	}
	const u_char* payload = udph+LIBNET_UDP_H+LIBNET_UDP_DNSV4_H;
	const u_char *end = payload + len ;
	//printf("DNS flags=%d/%d qd=%d an=%d, len=%d\n", dns->flags, dns->flags&0x80, qd, an, len);
	if ((dns->flags&0x80)==0) return; // DNS query, we only want responses.
	if (!an) return; // response is empty, probably responding with an error
	
	/* Parse the Question section */
	#define BUFSIZE 1024 // needs to be big enough to hold pkt payload
	u_char *tmp, *label=NULL, buf[BUFSIZE];
	uint16_t qtype = 0;

	tmp = (u_char *)payload;
	int i;
	for (i=0;i<qd;i++) {
		/* Get the first question's label and question type */
		if (!qtype) {
			label = dns_label_to_str(&tmp, buf, BUFSIZE, payload, end);
			tmp++;
			qtype = ntohs(*(uint16_t *)tmp);
			//printf("%d %s\n", qtype,label);
		} else {
			if (*tmp & 0xc0) tmp += 2;
			else tmp = skip_dns_label(tmp);
		}

		/* Skip type and class */
		tmp += 4;
		if (tmp >= end) return;
	}
	
	/* Output the answer corresponding to the question */
	//printf("qtype %d, an %d\n", qtype, an);
	if (!qtype) return;
	
	for (i=0;i< an; i++) {
		tmp = skip_dns_label(tmp);
		if (tmp + 10 > end) return;

		/* Get the type, and skip class and ttl */
		len = ntohs(*(uint16_t *)tmp); tmp += 8;
		if (len == qtype) break;

		/* Skip ahead to the next answer */
		tmp += ntohs(*(uint16_t *)tmp) + 2;
		if (tmp > end) return;
	}
	
	/* Get the data field length */
	//len = ntohs(*(uint16_t *)tmp);
	tmp += 2;

	/* Now, handle the data based on type */
	struct in6_addr addr;
	memset(&addr,0,sizeof(addr));
	int af=0;
	if(qtype==1) {// A
			memcpy(&addr,tmp,sizeof(struct in_addr));
			af=AF_INET;
	} else if (qtype==28) { // AAAA
			memcpy(&addr,tmp,sizeof(struct in6_addr));
			af=AF_INET6;
	} else {
		return;
	}
	append_dns(af,addr,(char*)label); 
	char n[INET6_ADDRSTRLEN];
	inet_ntop(af, &addr, n, INET6_ADDRSTRLEN);
	INFO2("DNS %d %s %s\n",af,label,n);
}
