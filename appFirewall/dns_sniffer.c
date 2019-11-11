
#include "dns_sniffer.h"

// circular list of reverse DNS lookups based on sniffed DNS reply packets
dns_item_t dns_cache[DNS_CACHE_SIZE];
int dns_cache_size=0;
int dns_cache_start=0;

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

int lookup_dns_row(int af, struct in6_addr addr) {
	int i;
	for (i=dns_cache_start; i<dns_cache_start+dns_cache_size; i++) {
		if (dns_cache[i%DNS_CACHE_SIZE].af != af)
			continue;
			
		/*if (af==AF_INET6){
		char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
		inet_ntop(dns_cache[i].af, &dns_cache[i].addr, sn, INET6_ADDRSTRLEN);
		inet_ntop(af, &addr, dn, INET6_ADDRSTRLEN);
		printf("af %d/%d addr %s/%s\n",dns_cache[i].af,af,sn,dn);
		}*/

		int len=sizeof(struct in_addr);
		if (af==AF_INET6) {
			len = sizeof(struct in6_addr);
		}
		if (memcmp(&dns_cache[i%DNS_CACHE_SIZE].addr.s6_addr,&addr.s6_addr,len)) {
			continue;
		}
		//printf("addr match\n");
		return i;
	}
	//printf("addr not found\n");
	return -1;
}

char* lookup_dns_name(int af, struct in6_addr addr) {
	int row=lookup_dns_row(af,addr);
	if (row>=0) {
		return dns_cache[row%DNS_CACHE_SIZE].name;
	} else {
		return NULL;
	}
}

void append_dns(int af, struct in6_addr addr, char* name) {
	int row=0;
	if ( (row=lookup_dns_row(af,addr))>=0) {
		DEBUG2("append_dns() item %s exists, overwriting.\n", name);
		strcpy(dns_cache[row%DNS_CACHE_SIZE].name,name);
		return;
	}
	if (dns_cache_size == DNS_CACHE_SIZE) {
		dns_cache_start++;
		dns_cache_size--;
	}
	int end = dns_cache_start+dns_cache_size;
	dns_cache[end%DNS_CACHE_SIZE].af = af;
	memcpy(&dns_cache[end%DNS_CACHE_SIZE].addr,&addr,sizeof(addr));
	strcpy(dns_cache[end%DNS_CACHE_SIZE].name,name);
	dns_cache_size++;
}

void save_dns_cache(void) {
	char path[1024]; strcpy(path,get_path());
	FILE *fp = fopen(strcat(path,DNSFILE),"w");
	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", DNSFILE, strerror(errno));
		return;
	}
	int i;
	int res = (int)fwrite(&dns_cache_start,sizeof(dns_cache_start),1,fp);
	if (res<1) {
		WARN("Problem saving start to %s: %s\n", DNSFILE,strerror(errno));
		return;
	}
	res = (int)fwrite(&dns_cache_size,sizeof(dns_cache_size),1,fp);
	if (res<1) {
		WARN("Problem saving size to %s: %s\n", DNSFILE,strerror(errno));
		return;
	}
	for(i = dns_cache_start; i < dns_cache_start+dns_cache_size; i++){
		int res=(int)fwrite(&dns_cache[i%DNS_CACHE_SIZE],sizeof(dns_item_t),1,fp);
		if (res<1) {
			WARN("Problem saving %s: %s\n", DNSFILE, strerror(errno));
			break;
		}
	}
	fclose(fp);
}

void load_dns_cache(void) {
	//return;
	char path[1024]; strcpy(path,get_path());
	FILE *fp = fopen(strcat(path,DNSFILE),"r");
	if (fp==NULL) {
		WARN("Problem opening %s for reading: %s\n", DNSFILE, strerror(errno));
		return;
	}
	fread(&dns_cache_start,sizeof(dns_cache_start),1,fp);
	fread(&dns_cache_size,sizeof(dns_cache_size),1,fp);
	int i;
	dns_cache_start=0; // might as well reset
	for(i = 0; i < dns_cache_size; i++){
		int res=(int)fread(&dns_cache[i%DNS_CACHE_SIZE],sizeof(dns_item_t),1,fp);
		if (res<1) {
			WARN("Problem loading %s: %s", DNSFILE, strerror(errno));
			break;
		}
	}
	if (i<dns_cache_size) {
		WARN("Read too few records from %s: expected %d, got %d\n",DNSFILE,dns_cache_size,i);
		dns_cache_size = i;
	}
	fclose(fp);
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
	u_char *tmp, *label=NULL, buf[BUFSIZE];
	uint16_t qtype = 0;

	tmp = (u_char *)payload;
	int i;
	for (i=0;i<qd;i++) {
		/* Get the first question's label and question type */
		if (!qtype) {
			label = dns_label_to_str(&tmp, buf, BUFSIZ, payload, end);
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
	char n[256];
	inet_ntop(af, &addr, n, INET6_ADDRSTRLEN);
	//printf("DNS %s %s\n",label,n);
}
