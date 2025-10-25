#include <stdio.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "libnet.h"
#include <pcap.h>

#define ERR(fmt,args ...) do{char buf[32]; fprintf(stderr,"%s ERROR: ",now(buf)); fprintf(stdout, fmt,args);}while(0)
#define WARN(args ...) do{char buf[32];fprintf(stderr,"%s WARNING: ",now(buf)); fprintf(stdout, args);}while(0)
#define INFO(args ...) if (verbose) do{char buf[32]; fprintf(stdout, "%s: ",now(buf));fprintf(stdout, args);}while(0)
#define INFO2(args ...) if (verbose>1) do{fprintf(stdout, args);}while(0)
#define DEBUG2(args ...) if (verbose>2) fprintf(stdout, args)

#define MAX_INTS 5 // max number of interfaces to monitor
#define STR_SIZE 1024

typedef struct libnet_data_t {
	libnet_t *l4, *l6, *l4_hdr, *l6_hdr;  // libnet state
	libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, tcp4_hdr_ptag, ip4_hdr_ptag,tcp6_hdr_ptag, ip6_hdr_ptag, eth_ptag;
	char last_intf[STR_SIZE];
	uint8_t last_eth[ETHER_ADDR_LEN];
	pcap_t* pd;
} libnet_data_t;

int get_interfaces(char intf[MAX_INTS][STR_SIZE], struct sockaddr_storage intf_addr[MAX_INTS][MAX_INTS], int num_addr[MAX_INTS], uint8_t eth[MAX_INTS][ETHER_ADDR_LEN], int use_pktap) {
	// get list of useful interfaces (IPv4 or IPv6 and not link-local)
	/*FILE *fp = popen("/sbin/route get default default | /usr/bin/grep interface","r");
	char* interface=NULL, buf[1024];
	if (fp != NULL) {
  	if (fgets(buf, sizeof(buf), fp)!=NULL) {
  		char* c = strstr(buf,":");
  		if (c!= NULL) {
  			interface = trimwhitespace(c+1);
			}
		}
		pclose(fp);
	}
	if (interface) {
		INFO("found default route interface: %s\n",interface);
		intf = interface;
	} else {
  // try using getifaddrs().  this will likely fail too if
  // call to route didn't work
  */
  
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
			//printf("got mac address for %s\n",dev->ifa_name);
			uint8_t* ptr = (uint8_t*)LLADDR((struct sockaddr_dl *)(dev)->ifa_addr);
			memcpy(temp_eth[temp_count],ptr,ETHER_ADDR_LEN);
			strlcpy(temp_ifname[temp_count],dev->ifa_name,STR_SIZE);
			temp_count++;
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
			if (j<temp_count) memcpy(eth[i],temp_eth[j],ETHER_ADDR_LEN);
		}
	}
	/*if (intf) {
		int i,j;
		for (i=0; i<count; i++) {
			printf("%s %d\n",intf[i],num_addr[i]);
			for (j=0; j<num_addr[i]; j++) {
				print_sockaddr((struct sockaddr*)&intf_addr[i][j]);
			}
		}
	}*/
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
		return 0;
	}

	/*char dn[INET6_ADDRSTRLEN];
	printf("snd_rst()dest address %s (src %s\n",inet_ntop(c->af,&c->src_addr,dn,INET6_ADDRSTRLEN),inet_ntop(c->af,&c->dst_addr,sn,INET6_ADDRSTRLEN));*/

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
	if (i<n) {
		strlcpy(str,temp_interfaces[i],len);
		memcpy(eth,temp_eth[i],ETHER_ADDR_LEN);
		return str;
	} else
		return NULL;
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
	
	ld->l6_hdr=libnet_init(LIBNET_RAW6,NULL,err_buf);
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
	uint8_t eth_src[ETHER_ADDR_LEN] = {0};
	eth_src[0]=0x70;
	eth_src[1]=0x4d;
	eth_src[2]=0x7b;
	eth_src[3]=0x95;
	eth_src[4]=0x14;
	eth_src[5]=0xc0;
	//70:4d:7b:95:14:c0
	*eth_ptag = libnet_build_ethernet(
		eth_dst,      /* ethernet destination */
		eth_src,      /* ethernet source */
		ETHERTYPE_IP,          /* protocol type */
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
		*ip_ptag = libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H+len,
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
		*ip_ptag = libnet_build_ipv6(0,0,LIBNET_TCP_H,
																 IPPROTO_TCP, 64,
																 s, d,
																 NULL, 0, l, *ip_ptag);
	}
	return *ip_ptag;
}

int main(int argc, char *argv[]) {

	libnet_ptag_t *tcp_ptag, *ip_ptag, *tcp_hdr_ptag, *ip_hdr_ptag, *eth_ptag;
	libnet_t *l=NULL, *l_hdr=NULL;
	l= ld->l6; tcp_ptag=&ld->tcp6_ptag; ip_ptag=&ld->ip6_ptag;
	l_hdr = ld->l6_hdr; tcp_hdr_ptag=&ld->tcp6_hdr_ptag; ip_hdr_ptag=&ld->ip6_hdr_ptag;
	eth_ptag = &ld->eth_ptag;
	
	uint8_t flags=TH_RST;
	if ((*tcp_hdr_ptag = libnet_build_tcp(c->dport,c->sport,c->ack+1,c->seq,flags,
																	 0, 0, 0, LIBNET_TCP_H, NULL, 0, l_hdr, *tcp_hdr_ptag))==-1) {
		ERR("libnet_build_tcp_hdr(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (append_ipheader(c->af, &c->dst_addr, &c->src_addr, l_hdr, ip_hdr_ptag, 0)==-1) {
		ERR("libnet_build_ip_hdr() %s\n", libnet_geterror(l)); goto err;
	}
		char buf[STR_SIZE]; uint8_t eth_buf[ETHER_ADDR_LEN];
		char* intf; uint8* eth;
		intf = find_intf(c, buf, STR_SIZE, eth_buf);
		eth = eth_buf;
		if ((intf != NULL) && (eth!=NULL)) {
			// we found an interface with address matching
			append_ether(l_hdr, eth_ptag, eth);
			uint8_t *packet = NULL; uint32_t len;
			if (libnet_pblock_coalesce(l_hdr, &packet, &len)<0) {
				WARN("libnet_pblock_coalesce() of IPv6 RST to self failed: %s\n",libnet_geterror(l_hdr));
				return -1;
			} else {
				if (strcmp(ld->last_intf,intf) != 0) {
					if (ld->pd) pcap_close(ld->pd);
					strlcpy(ld->last_intf,intf,STR_SIZE);
					memcpy(ld->last_eth,eth,ETHER_ADDR_LEN);
					setup_pd(intf, &ld->pd, "tcp", 0);
				}
				if (pcap_inject(ld->pd,packet,len)==PCAP_ERROR) {
					WARN("pcap_inject() of IPv6 RST to self failed: %s\n",pcap_geterr(ld->pd));
					return -1;
				}
			}
		} else {
			char dn[INET6_ADDRSTRLEN],sn[INET6_ADDRSTRLEN];
			WARN("snd_rst() couldn't find interface matching dest address %s (src %s) of IPv6 RST to self\n",inet_ntop(c->af,&c->src_addr,dn,INET6_ADDRSTRLEN),inet_ntop(c->af,&c->dst_addr,sn,INET6_ADDRSTRLEN));
			return -1;

		}
	}

	return 1;
	
err:
	free_libnet(ld); init_libnet(ld);
	return -1;
}
