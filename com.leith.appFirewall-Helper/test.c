#include <stdio.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "libnet.h"
#include <pcap.h>
#include <net/if_dl.h>

#define ERR(fmt,args ...) do{ fprintf(stdout, fmt,args);}while(0)
#define WARN(args ...) do{ fprintf(stdout, args);}while(0)
#define INFO(args ...) if (verbose) do{fprintf(stdout, args);}while(0)
#define INFO2(args ...) if (verbose>1) do{fprintf(stdout, args);}while(0)
#define DEBUG2(args ...) if (verbose>2) fprintf(stdout, args)

#define MAX_INTS 5 // max number of interfaces to monitor
#define STR_SIZE 1024
#define SNAPLEN 512
const static int verbose=3;          // debugging level
int pcap_set_want_pktap(pcap_t *, int);
int pcap_set_filter_info(pcap_t *, const char *, int, bpf_u_int32);


typedef struct libnet_data_t {
	libnet_t *l4, *l6, *l4_hdr, *l6_hdr;  // libnet state
	libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, tcp4_hdr_ptag, ip4_hdr_ptag,tcp6_hdr_ptag, ip6_hdr_ptag, eth_ptag;
	char last_intf[STR_SIZE];
	uint8_t last_eth[ETHER_ADDR_LEN];
	pcap_t* pd;
} libnet_data_t;

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	uint16_t sport, dport; // local and remote ports
	int udp;
	uint32_t seq, ack;
	struct timeval ts, start;
} conn_raw_t;

void print_sockaddr(struct sockaddr* daddr) {
	char addr_name[INET6_ADDRSTRLEN];
	if (daddr->sa_family == AF_INET) {
		inet_ntop(daddr->sa_family, &((struct sockaddr_in*)daddr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
	} else if (daddr->sa_family == AF_INET6) {
		inet_ntop(daddr->sa_family, &((struct sockaddr_in6*)daddr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
	}
	printf("%s\n",addr_name);
}

int get_interfaces(char intf[MAX_INTS][STR_SIZE], struct sockaddr_storage intf_addr[MAX_INTS][MAX_INTS], int num_addr[MAX_INTS], uint8_t eth[MAX_INTS][ETHER_ADDR_LEN], int use_pktap) {

  // get every IPv4/IPv6 interface
	struct ifaddrs *ifap;
	if (getifaddrs(&ifap)<0) {
		ERR("Couldn't get list of interfaces from getifaddrs() for pcap sniffer: %s", strerror(errno));
		// should this be fatal ?
		return -1;
	}
	struct ifaddrs *dev;
	int count=0, temp_count=0;
	uint8_t temp_eth[MAX_INTS][ETHER_ADDR_LEN];
	char temp_ifname[MAX_INTS][STR_SIZE];
	for(dev=ifap; dev; dev=dev->ifa_next) {
		DEBUG2("interface %s ...",dev->ifa_name);
		if (dev-> ifa_flags & IFF_LOOPBACK) {DEBUG2("loopback\n"); continue;}
		// point to point link is likely a vpn, so let's listen to it
		//if (dev-> ifa_flags & IFF_POINTOPOINT) {DEBUG2("point to point\n"); continue;}
		if (dev->ifa_flags&IFF_NOARP) {DEBUG2("no ARP\n"); continue;}
		if ((dev->ifa_flags&IFF_UP)==0) {DEBUG2("not up\n"); continue;}
		if ((dev->ifa_flags&IFF_BROADCAST)==0) {
			if (!(dev-> ifa_flags & IFF_POINTOPOINT)) {
				DEBUG2("no valid broadcast addr\n");
				continue;
			}
		}
		//if (!dev->ifa_netmask) {printf("no valid netmask\n"); continue;}
		struct sockaddr *daddr = dev->ifa_addr;
		char addr_name[INET6_ADDRSTRLEN];
		int af = daddr->sa_family;
		if (af == AF_INET) {
			if ( ((struct sockaddr_in*)daddr)->sin_addr.s_addr == htonl(INADDR_ANY)) continue;
			inet_ntop(af, &((struct sockaddr_in*)daddr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
		} else if (af == AF_INET6) {
			inet_ntop(af, &((struct sockaddr_in6*)daddr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
		} else if (af == AF_LINK) {
			// extract the MAC address
			printf("got mac address for %s\n",dev->ifa_name);
			uint8_t* ptr = (uint8_t*)LLADDR((struct sockaddr_dl *)(dev)->ifa_addr);
			int k;
			for (k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",*(ptr+k));
			printf("\n%lu %d\n", sizeof(temp_eth[temp_count]),ETHER_ADDR_LEN);
			if (temp_count==MAX_INTS) continue;
			memcpy(temp_eth[temp_count],ptr,ETHER_ADDR_LEN);
			for (k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",*(temp_eth[temp_count]+k));
			strlcpy(temp_ifname[temp_count],dev->ifa_name,STR_SIZE);
			if (temp_count<MAX_INTS) temp_count++;
			continue;
		} else {DEBUG2("not IPv4/IPv6\n"); continue;}
		char* mask6="fe80:", *mask4="169.254";
		if ((strncmp(mask6, addr_name, strnlen(mask6,STR_SIZE)) == 0)
				|| (strncmp(mask4, addr_name, strnlen(mask4,STR_SIZE)) == 0)) {
			DEBUG2("link local addr\n");
			continue; // ignore link local addresses
		}
		DEBUG2("%s addr %s found\n",dev->ifa_name,addr_name);
		if (intf == NULL)  {
			count++;
		} else {
			char name[STR_SIZE];
			if (use_pktap) {
				// prepend interface name with pktap,
				strlcpy(name,"pktap,",STR_SIZE);
				//strlcpy(intf[count],"iptap,",STR_SIZE);
			} else {
				strlcpy(name,"",STR_SIZE);;
			}
			strlcat(name,dev->ifa_name,STR_SIZE);
			int i;
			for (i=0; i<count; i++) {
				if (strcmp(intf[i],name)==0) break;
			}
			// check that we don't already have this interface in our list
			if (i<count) {
				if (num_addr[i]<MAX_INTS) {
					//printf("count=%d, i=%d, %d\n",count, i, num_addr[i]);
					//print_sockaddr(dev->ifa_addr);
					if (af==AF_INET)
						memcpy(&intf_addr[i][num_addr[i]],dev->ifa_addr,sizeof(struct sockaddr_in));
					else
						memcpy(&intf_addr[i][num_addr[i]],dev->ifa_addr,sizeof(struct sockaddr_in6));
					//print_sockaddr((struct sockaddr*)&intf_addr[i][num_addr[i]]);
					num_addr[i]++;
				} else {
					WARN("get_interfaces() number of addresses is >%d for interface %s\n",MAX_INTS, dev->ifa_name);
				}
			} else {
				//printf("count=%d\n",count);
				strlcpy(intf[count],name,STR_SIZE);
				//print_sockaddr(dev->ifa_addr);
				if (af==AF_INET)
					memcpy(&intf_addr[count][0],dev->ifa_addr,sizeof(struct sockaddr_in));
				else
					memcpy(&intf_addr[count][0],dev->ifa_addr,sizeof(struct sockaddr_in6));
				//print_sockaddr((struct sockaddr*)&intf_addr[count][0]);
				num_addr[count] = 1;
				if (count < MAX_INTS) {
					count++;
				} else {
					WARN("get_interfaces() >%d interfaces found\n", MAX_INTS);
					break;
				}
			}
		}
	}
	freeifaddrs(ifap);
	//}
	// now try to match up MAC addresses
	if (eth && intf) {
		int i,j;
		for (i=0; i<count; i++) {
			for (j=0; j<temp_count; j++) {
				if (strcmp(intf[i],temp_ifname[j])==0) break;
			}
			int k;for (k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",*(temp_eth[j]+k));
			if (j<temp_count) memcpy(eth[i],temp_eth[j],ETHER_ADDR_LEN);
			for (k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",*(eth[i]+k));
		}
	}
	printf("get_interfaces\n");
	if (intf) {
		int i,j;
		for (i=0; i<count; i++) {
			printf("%s %d\n",intf[i],num_addr[i]);
			for (j=0; j<num_addr[i]; j++) {
				print_sockaddr((struct sockaddr*)&intf_addr[i][j]);
				int k;for (k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",*(eth[i]+k));
			}
		}
	}
	printf("done count=%d\n", count);
	return count;
}

char* find_intf(conn_raw_t* c, char* str, int len, uint8_t eth[ETHER_ADDR_LEN]) {
	// find interface used by src of connection (assuming conn is outgoing)
	char temp_interfaces[MAX_INTS][STR_SIZE];
	struct sockaddr_storage temp_addr[MAX_INTS][MAX_INTS];
	int temp_num_addr[MAX_INTS];
	uint8_t temp_eth[MAX_INTS][ETHER_ADDR_LEN];
	int n=0;
	if ( (n=get_interfaces(temp_interfaces, temp_addr, temp_num_addr, temp_eth, 0))<=0) {
		printf("n=%d\n",n);
		return 0;
	}
	printf("n=%d\n",n);
	char dn[INET6_ADDRSTRLEN];
	printf("c dest address %s\n",inet_ntop(c->af,&c->src_addr,dn,INET6_ADDRSTRLEN));

	int i,j;
	for (i=0; i<n; i++) {
		//printf("%s (%d) ",temp_interfaces[i],temp_num_addr[i]);
		for (j=0; j<temp_num_addr[i];j++) {
			/*if (temp_addr[i][j].ss_family==AF_INET) {
				printf("%s ",inet_ntop(
				temp_addr[i][j].ss_family,
				&((struct sockaddr_in*)&temp_addr[i][j])->sin_addr,
				dn,INET6_ADDRSTRLEN));
			} else {
				printf("%s ",inet_ntop(
				temp_addr[i][j].ss_family,
				&((struct sockaddr_in6*)&temp_addr[i][j])->sin6_addr,
				dn,INET6_ADDRSTRLEN));
			}*/
			if (temp_addr[i][j].ss_family != c->af) continue;
			if (c->af == AF_INET6) {
				if (memcmp(&c->src_addr, &((struct sockaddr_in6*)&temp_addr[i][j])->sin6_addr, 16)==0) break;
			} else {
				if (memcmp(&c->src_addr, &((struct sockaddr_in*)&temp_addr[i][j])->sin_addr, 4)==0) break;
			}
		}
		//printf("\n");
		if (j<temp_num_addr[i]) break;
	}
	printf("i=%d, n=%d\n",i,n);
	if (i<n) {
		strlcpy(str,temp_interfaces[i],len);
		memcpy(eth,temp_eth[i],ETHER_ADDR_LEN);
		return str;
	} else
		return NULL;
}

int get_DLT_offset2(int datalink) {
	int offset=0;
	switch (datalink) {
		case DLT_EN10MB:
			//printf("DLT_EN10MB\n");
			offset = 14;
			break;
		case DLT_IEEE802:
			offset = 22;
			break;
		case DLT_NULL:
			//printf("DLT_NULL\n");
			offset = 4;
			break;
		case DLT_SLIP:
			offset = 16;
			break;
		case DLT_PPP:
		case DLT_PPP_BSDOS:
		case DLT_PPP_SERIAL:
		case DLT_PPP_ETHER:
			//printf("DLT_PPP %d %d %d %d\n",DLT_PPP,DLT_PPP_BSDOS,DLT_PPP_SERIAL,DLT_PPP_ETHER);
			offset = 4;
			break;
		case DLT_RAW:
			//printf("DLT_RAW\n");
			offset = 0;
			break;
		case DLT_FDDI:
			offset = 21;
			break;
		case DLT_ENC:
			offset = 12;
			break;
		case DLT_IPNET:
			offset = 24;
			break;
		case DLT_PKTAP: // apple special header
			//printf("DLT_PKTAP\n");
			offset = 0; // dummy, need to read header to find actual offset
			break;
		default:
			ERR("Unknown datalink type: %d\n", datalink);
			return -1;
		}
		return offset;
}

int get_DLT_offset(pcap_t *pd, int use_pktap) {

/*
	// dump out available link layer types for pd
	int *l;
	int n = pcap_list_datalinks(pd,&l);
	printf("DLTs n=%d:\n",n);
	for (int i=0; i<n; i++) printf("%d ",l[i]);
	pcap_free_datalinks(l);
	printf("\n");*/
	
	int datalink;
  if ((datalink = pcap_datalink(pd)) < 0){
    WARN("Cannot obtain datalink information: %s", pcap_geterr(pd));
    return -1;
	}

	if (use_pktap && (datalink != DLT_PKTAP)) {
		// TO DO: recover better from this error
		ERR("PKTAP enabled but DLT (%d) is not DLT_PKTAP (%d)!\n", datalink, DLT_PKTAP);
		return -1;
	}
	return get_DLT_offset2(datalink);
}

int setup_pd(char* intf, pcap_t **pd, char* filter_exp, int use_pktap) {
	// initialise a pcap listener for an available interfaces
	char ebuf[PCAP_ERRBUF_SIZE];

	// create pcap listener
	if ((*pd = pcap_create(intf, ebuf)) == NULL) {
		ERR("Couldn't create pcap sniffer %s\n",ebuf);
		return -1;
	}

	if (pcap_set_snaplen(*pd,SNAPLEN)!=0) {
		WARN("Couldn't set snaplen on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	if (pcap_set_immediate_mode(*pd,1)!=0) { // deliver sniffed packets immediately.
		WARN("Couldn't set immediate mode on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	#define BUFFER_SIZE 2097152*8  // default is 2M=2097152, but we increase it to 16M
	pcap_set_buffer_size(*pd, BUFFER_SIZE);

	if (use_pktap) pcap_set_want_pktap(*pd, 1);

	// now that its configured, fire up listener
	int res;
	if ((res=pcap_activate(*pd))!=0) {
		if (res<0) {
			ERR("Couldn't activate pcap sniffer: %s\n",pcap_geterr(*pd));
			return -1;
		} else {
			// activate was successful but had warnings
			WARN("Problem activating pcap sniffer: %s\n",pcap_geterr(*pd));
		}
	}

	if (use_pktap) {
		// not sure if this is even needed,
		// filters don't seem to work with pktap anyway !
		if (pcap_set_filter_info(*pd, filter_exp, 0, PCAP_NETMASK_UNKNOWN)<0) {
			ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
			return -1;
		}
	} else {
		struct bpf_program fp;
		if (pcap_compile(*pd, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
		ERR("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
			return -1;
		}
		if (pcap_setfilter(*pd, &fp) == PCAP_ERROR) {
			ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
		return -1;
		}
	}
	return 1;
}

void init_libnet(libnet_data_t *ld) {
	// now initialise libnet packet processing data structure
	char err_buf[LIBNET_ERRBUF_SIZE];
	
	INFO("init_libnet\n");
	
	ld->tcp4_ptag=LIBNET_PTAG_INITIALIZER; ld->ip4_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp4_hdr_ptag=LIBNET_PTAG_INITIALIZER; ld->ip4_hdr_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp6_ptag=LIBNET_PTAG_INITIALIZER; ld->ip6_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp6_hdr_ptag=LIBNET_PTAG_INITIALIZER; ld->ip6_hdr_ptag=LIBNET_PTAG_INITIALIZER;
	ld->eth_ptag=LIBNET_PTAG_INITIALIZER;

	ld->l4=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4==NULL) {
		ERR("libnet_init() IPv4 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	ld->l6=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (ld->l6==NULL) {
		ERR("libnet_init() IPv6 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	
	// we set IP_HDRINCL socket option for this socket, so have to construct
	// full IP header but this allows us to send to self (when not set the
	// kernel constructs source part of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	ld->l4_hdr=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4_hdr==NULL) {
		ERR("libnet_init() IPv4 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	int n = 1;
	if (setsockopt(ld->l4_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		WARN("libnet setsockopt IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}
	
	ld->l6_hdr=libnet_init(LIBNET_LINK,"en0",err_buf);
	if (ld->l6_hdr==NULL) {
		ERR("libnet_init() IPv6 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	/*
	//IP_HDRINCL not supported on MAC OS for IPv6
	n = 1;
	if (setsockopt(ld->l6_hdr->fd, IPPROTO_IPV6, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt() IPv6 IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}*/

	ld->pd = NULL; memset(ld->last_intf,0,STR_SIZE);
}

void free_libnet(libnet_data_t *ld) {
	INFO("free_libnet()\n");
	if (ld->l4) libnet_destroy(ld->l4);
	if (ld->l6) libnet_destroy(ld->l6);
	if (ld->l4_hdr) libnet_destroy(ld->l4_hdr);
	if (ld->l6_hdr) libnet_destroy(ld->l6_hdr);
	if (ld->pd) pcap_close(ld->pd);
}

libnet_ptag_t append_ether(libnet_t *l, libnet_ptag_t *eth_ptag, uint8_t eth_dst[ETHER_ADDR_LEN]) {
	uint8_t eth_src[ETHER_ADDR_LEN];
	eth_src[0]=0x70;
	eth_src[1]=0x4d;
	eth_src[2]=0x7b;
	eth_src[3]=0x95;
	eth_src[4]=0x14;
	eth_src[5]=0xc0;
	int i; for(i=0; i<ETHER_ADDR_LEN;i++) printf("%02x ",eth_dst[i]);
	printf("\n");
	*eth_ptag = libnet_build_ethernet(
		eth_dst,      /* ethernet destination */
		eth_dst,      /* ethernet source */
		ETHERTYPE_IPV6,          /* protocol type */
		NULL,                  /* payload */
		0,                     /* payload size */
		l,                     /* libnet handle */
		0);                    /* libnet id */
	return *eth_ptag;
}

libnet_ptag_t append_ipheader(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr, libnet_t *l, libnet_ptag_t *ip_ptag, uint16_t len) {
	// construct IP header for RST packet to remote host
	if (af==AF_INET) {
		uint32_t d,s;
		memcpy(&s,&src_addr->s6_addr,4);
		memcpy(&d,&dst_addr->s6_addr,4);
		//libnet_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,
		//uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,
		//const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
		*ip_ptag = libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_UDP_H+len,
																 0, 0, 0, 64, IPPROTO_TCP,0,
																 s, d,
																 NULL, 0, l, *ip_ptag);
	} else {
		//libnet_build_ipv6(uint8_t tc, uint32_t fl, uint16_t len, uint8_t nh,
		//uint8_t hl, struct libnet_in6_addr src, struct libnet_in6_addr dst,
		//const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
		struct libnet_in6_addr s, d;
		memcpy(&s,src_addr,16);
		memcpy(&d,dst_addr,16);
		*ip_ptag = libnet_build_ipv6(0,0,LIBNET_UDP_H+len,
																 IPPROTO_UDP, 64,
																 s, d,
																 NULL, 0, l, *ip_ptag);
	}
	return *ip_ptag;
}

int main(int argc, char *argv[]) {

	conn_raw_t c2;
	c2.af = AF_INET6;
	inet_pton(c2.af, "2a02:8084:51bd:e6f0:432:c98c:bc17:ab1d", &c2.src_addr);
	c2.sport = 2000;
	inet_pton(c2.af, "2a00:1450:400b:c00::66", &c2.dst_addr);
	c2.dport = 443;
	
	conn_raw_t *c = &c2;
	
	libnet_data_t ld2;
	libnet_data_t *ld=&ld2;
	init_libnet(ld);
	
	libnet_ptag_t *tcp_ptag, *ip_ptag, *tcp_hdr_ptag, *ip_hdr_ptag, *eth_ptag;
	libnet_t *l=NULL, *l_hdr=NULL;
	l= ld->l6; tcp_ptag=&ld->tcp6_ptag; ip_ptag=&ld->ip6_ptag;
	l_hdr = ld->l6_hdr; tcp_hdr_ptag=&ld->tcp6_hdr_ptag; ip_hdr_ptag=&ld->ip6_hdr_ptag;
	eth_ptag = &ld->eth_ptag;
	
	printf("udp\n");
	uint8_t flags=0; //TH_RST;
	const char *tbuf = "hello"; uint16_t len = (uint16_t)strlen(tbuf);
	
	if ((*tcp_hdr_ptag = libnet_build_udp((c->dport),(c->sport),LIBNET_UDP_H+len,0, (uint8_t*)tbuf, len, l_hdr, *tcp_hdr_ptag))==-1) {
		ERR("libnet_build_tcp_hdr(): %s\n", libnet_geterror(l_hdr)); exit(1);
	}

	printf("ip\n");
	if (append_ipheader(c->af, &c->dst_addr, &c->src_addr, l_hdr, ip_hdr_ptag, len)==-1) {
		ERR("libnet_build_ip_hdr() %s\n", libnet_geterror(l)); exit(1);
	}
		char buf[STR_SIZE]; uint8_t eth_buf[ETHER_ADDR_LEN];
		char* intf; uint8_t* eth;
		printf("find_intf\n");
		intf = find_intf(c, buf, STR_SIZE, eth_buf);
		eth = eth_buf;
		if ((intf != NULL) && (eth!=NULL)) {
			// we found an interface with address matching
			printf("eth\n");
			append_ether(l_hdr, eth_ptag, eth);
			uint8_t *packet = NULL; uint32_t pkt_len;
			/*if (libnet_pblock_coalesce(l_hdr, &packet, &pkt_len)<0) {
				WARN("libnet_pblock_coalesce() of IPv6 RST to self failed: %s\n",libnet_geterror(l_hdr));
				return -1;
			} else {
				if (strcmp(ld->last_intf,intf) != 0) {
					printf("setup pd\n");
					if (ld->pd) pcap_close(ld->pd);
					strlcpy(ld->last_intf,intf,STR_SIZE);
					memcpy(ld->last_eth,eth,ETHER_ADDR_LEN);
					//setup_pd(intf, &ld->pd, "tcp", 0);
				}
				printf("inject\n");
				if (pcap_inject(ld->pd,packet,pkt_len)==PCAP_ERROR) {
					WARN("pcap_inject() of IPv6 RST to self failed: %s\n",pcap_geterr(ld->pd));
					return -1;
				}
				pcap_close(ld->pd);
				*/
				if (libnet_write(l_hdr)<0) {
					printf("%s",libnet_geterror(l_hdr));
				}
				//free_libnet(ld);
			//}
		} else {
			char dn[INET6_ADDRSTRLEN],sn[INET6_ADDRSTRLEN];
			WARN("snd_rst() couldn't find interface matching dest address %s (src %s) of IPv6 RST to self\n",inet_ntop(c->af,&c->src_addr,dn,INET6_ADDRSTRLEN),inet_ntop(c->af,&c->dst_addr,sn,INET6_ADDRSTRLEN));
			return -1;

		}
	return 1;
	
}
