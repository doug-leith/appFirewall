//
//  pcap_sniffer.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "pcap_sniffer.h"

//globals
static time_t stats_time; // time when last asked pcap for stats
static int p_sock, p_sock2=-1;
static int pid = -1;
static pthread_t listener_thread; // handle to listener thread
static int are_sniffing = 0;

// syns and syn-acks, DNS and mDNS, UDP on ports 443 likely to be quic
// tcpflags doesn't work for ipv6, sigh.
static char *filter_exp = "\
(udp and port 53) or (udp and port 5353) \
or (tcp and (tcp[tcpflags]&tcp-syn!=0)) \
or (ip6[6] == 6 and (ip6[53]&tcp-syn!=0)) \
or (udp and port 443)";

void close_sniffer_sock() {
	close(p_sock); close(p_sock2);
}

char* get_default_route_intf() {
	// get the interface used by default route
	FILE *fp = popen("/sbin/route get default default | /usr/bin/grep interface","r");
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
		return interface;
	}	else
		return NULL;
}

void print_sockaddr(struct sockaddr* daddr) {
	char addr_name[INET6_ADDRSTRLEN];
	if (daddr->sa_family == AF_INET) {
		inet_ntop(daddr->sa_family, &((struct sockaddr_in*)daddr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
	} else if (daddr->sa_family == AF_INET6) {
		inet_ntop(daddr->sa_family, &((struct sockaddr_in6*)daddr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
	}
	printf("%s\n",addr_name);
}

char* get_intf_name(char* ifa_name, int use_pktap, char* name) {
	if (use_pktap) {
		// prepend interface name with pktap,
		//strlcpy(name,"pktap,",STR_SIZE);
		strlcpy(name,"iptap,",STR_SIZE); // we've no need for link-layer header
	} else {
		strlcpy(name,"",STR_SIZE);;
	}
	strlcat(name,ifa_name,STR_SIZE);
	return name;
}

int get_interfaces(interface_t intf[MAX_INTS], int use_pktap) {
	// get list of useful interfaces (IPv4 or IPv6, up and not link-local)
	struct ifaddrs *ifap;
	if (getifaddrs(&ifap)<0) {
		ERR("Couldn't get list of interfaces from getifaddrs() for pcap sniffer: %s", strerror(errno));
		return -1; // should this be fatal ?
	}
	struct ifaddrs *dev;
	int count=0, temp_count=0;
	uint8_t temp_eth[MAX_MACS][ETHER_ADDR_LEN];
	int temp_dlt[MAX_MACS];
	char temp_ifname[MAX_MACS][STR_SIZE];
	for(dev=ifap; dev; dev=dev->ifa_next) {
		DEBUG2("interface %s ...",dev->ifa_name);
		if (dev-> ifa_flags&IFF_LOOPBACK) {DEBUG2("loopback\n"); continue;}
		if (dev->ifa_flags&IFF_NOARP) {DEBUG2("no ARP\n"); continue;}
		if ((dev->ifa_flags&IFF_UP)==0) {DEBUG2("not up\n"); continue;}
		if ((dev->ifa_flags&IFF_BROADCAST)==0) {
			// point to point link is likely a vpn, so let's listen to it
			if (!(dev-> ifa_flags & IFF_POINTOPOINT)) { DEBUG2("no valid broadcast addr\n"); continue;}
		}
		//if (!dev->ifa_netmask) {printf("no valid netmask\n"); continue;}
		struct sockaddr *daddr = dev->ifa_addr;
		int af = daddr->sa_family;
		if (af == AF_LINK) {
			// extract the MAC address
			if (temp_count >= MAX_MACS) {
				WARN("get_interfaces() number of MAC addresses is >%d\n",MAX_MACS);
				continue;
			}
			unsigned short ifi_type = ((struct if_data*)dev->ifa_data)->ifi_type;
			if (ifi_type == IFT_ETHER) { // ethernet
				temp_dlt[temp_count] = DLT_EN10MB;
				uint8_t* ptr = (uint8_t*)LLADDR((struct sockaddr_dl *)(dev)->ifa_addr);
				memcpy(temp_eth[temp_count],ptr,ETHER_ADDR_LEN);
				//printf("%s :",dev->ifa_name);
				//int k; for(k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",temp_eth[temp_count][k]); printf("\n");
			} else if (ifi_type == IFT_LOOP) { // loopback
				temp_dlt[temp_count] = DLT_NULL;
			} else {DEBUG2("not ethernet or loopback\n"); continue; }
			get_intf_name(dev->ifa_name, use_pktap, temp_ifname[temp_count]);
			temp_count++;
			continue;
		}
		if ((af != AF_INET) && (af != AF_INET6)) {DEBUG2("not IPv4/IPv6\n"); continue;}

		// if get to here then its an interesting interface, let's look at the address
		char addr_name[INET6_ADDRSTRLEN];
		if (af == AF_INET) {
			if ( ((struct sockaddr_in*)daddr)->sin_addr.s_addr == htonl(INADDR_ANY)) continue;
			inet_ntop(af, &((struct sockaddr_in*)daddr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
		} else { // IPv6
			inet_ntop(af, &((struct sockaddr_in6*)daddr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
		}
		char* mask6="fe80:", *mask4="169.254";
		if ((strncmp(mask6, addr_name, strnlen(mask6,STR_SIZE)) == 0)
				|| (strncmp(mask4, addr_name, strnlen(mask4,STR_SIZE)) == 0)) {
			DEBUG2("link local addr\n");
			continue; // ignore link local addresses
		}
		DEBUG2("%s addr %s found\n",dev->ifa_name,addr_name);
		if (intf == NULL)  { // caller has just asked us to count the number of available interfaces
			count++;
		} else {  // caller wants interface details
			char name[STR_SIZE];
			get_intf_name(dev->ifa_name, use_pktap, name);
			// check that we don't already have this interface in our list
			int i;
			for (i=0; i<count; i++) {
				if (strcmp(intf[i].name,name)==0) break;
			}
			if (i<count) { // found a match, add new address to the list associated with existing interface
				if (intf[i].num_addr<MAX_INTS) {
					if (af==AF_INET)
						memcpy(&intf[i].addr[intf[i].num_addr],dev->ifa_addr,sizeof(struct sockaddr_in));
					else
						memcpy(&intf[i].addr[intf[i].num_addr],dev->ifa_addr,sizeof(struct sockaddr_in6));
					intf[i].num_addr++;
				} else {
					WARN("get_interfaces() number of addresses is >%d for interface %s\n",MAX_INTS, dev->ifa_name);
				}
			} else { // a new interface, add to our list
				strlcpy(intf[count].name,name,STR_SIZE);
				if (af==AF_INET)
					memcpy(&intf[count].addr[0],dev->ifa_addr,sizeof(struct sockaddr_in));
				else
					memcpy(&intf[count].addr[0],dev->ifa_addr,sizeof(struct sockaddr_in6));
				intf[count].num_addr = 1;
				intf[count].dlt = -1;
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
	// now try to match up the collected list of MAC addresses to the list of interfaces
	if (intf) {
		int i,j;
		for (i=0; i<count; i++) {
			for (j=0; j<temp_count; j++) {
				if (strcmp(intf[i].name,temp_ifname[j])==0) break;
			}
			if (j<temp_count) {
				//printf("Matched %s %d\n", intf[i].name, intf[i].dlt);
				intf[i].dlt = temp_dlt[j];
				if (temp_dlt[j] == DLT_EN10MB) {
					memcpy(intf[i].eth,temp_eth[j],ETHER_ADDR_LEN);
					//int k; for(k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",temp_eth[j][k]); printf("\n");
					//for(k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",intf[i].eth[k]); printf("\n");
				}
			}
		}
	}
	// for debugging
	/*if (intf) {
		int i,j;
		for (i=0; i<count; i++) {
			printf("%s %d\n",intf[i].name,intf[i].num_addr);
			for (j=0; j<intf[i].num_addr; j++) {
				print_sockaddr((struct sockaddr*)&intf[i].addr[j]);
			}
			printf("dlt=%d\n",intf[i].dlt);
			int k; for(k=0; k<ETHER_ADDR_LEN;k++) printf("%02x ",intf[i].eth[k]); printf("\n");
		}
	}*/
	return count;
}

interface_t* find_intf(conn_raw_t* c, interface_t* intf) {
	// find interface used by src of connection (assuming conn is outgoing)
	interface_t temp_intf[MAX_INTS];
	int n=0;
	if ( (n=get_interfaces(temp_intf, 0))<=0) {
		return 0;
	}
	int i,j;
	for (i=0; i<n; i++) {
		for (j=0; j<temp_intf[i].num_addr;j++) {
			if (temp_intf[i].addr[j].ss_family != c->af) continue;
			if (c->af == AF_INET6) {
				if (memcmp(&c->src_addr, &((struct sockaddr_in6*)&temp_intf[i].addr[j])->sin6_addr, 16)==0) break;
			} else {
				if (memcmp(&c->src_addr, &((struct sockaddr_in*)&temp_intf[i].addr[j])->sin_addr, 4)==0) break;
			}
		}
		if (j<temp_intf[i].num_addr) break;
	}
	if (i<n) {
		memcpy(intf,&temp_intf[i],sizeof(interface_t));
		return intf;
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
	// for debugging, dump out available link layer types for pd
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

int setup_pd(interface_t* intf, pcap_t **pd, char* filter_exp, int use_pktap) {
	// initialise a pcap listener for an available interfaces
	char ebuf[PCAP_ERRBUF_SIZE];

	// create pcap listener
	if ((*pd = pcap_create(intf->name, ebuf)) == NULL) {
		ERR("Couldn't create pcap sniffer %s\n",ebuf);
		return -1;
	}

	if (pcap_set_snaplen(*pd,SNAPLEN)!=0) {
		WARN("Couldn't set snaplen on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	if (pcap_set_immediate_mode(*pd,1)!=0) { // deliver sniffed packets immediately.
		WARN("Couldn't set immediate mode on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	pcap_set_buffer_size(*pd, PCAP_BUFFER_SIZE);

	if (use_pktap) pcap_set_want_pktap(*pd, 1); // APPLE libpcap call

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

int refresh_sniffers_list(sniffers_t *sn, char* filter_exp, int quiet) {
	// get an update on the available interfaces ...
	//struct timeval start; gettimeofday(&start, NULL);
	
	interface_t temp_intf[MAX_INTS];
	int n=0, extra=0;
	sniffers_t old_sn;
	memcpy(&old_sn,sn,sizeof(sniffers_t));
	memset(sn,0,sizeof(sniffers_t));
	sn->use_pktap = old_sn.use_pktap;
	if ( (n=get_interfaces(temp_intf, sn->use_pktap))<=0) {
		return 0;
	}
	int i;
	for (int j=0; j<n; j++) {
		// there's an assumption here that each interface appears at most
		// once in interfaces list, we enforce this via get_interfaces()
		for (i = 0; i<old_sn.num_pds; i++) {
			if (strcmp(old_sn.sn[i].intf.name, temp_intf[j].name)==0) break;
		}
		if (i<old_sn.num_pds) {
			// interface already has an existing sniffer
			sn->sn[sn->num_pds].pd = old_sn.sn[i].pd;
			memcpy(&sn->sn[sn->num_pds], &old_sn.sn[i], sizeof(sniffer_t));
			sn->num_pds++;
			old_sn.sn[i].pd = NULL; // mark as copied
			continue;
		}
		// a new interface has appeared
		if (sn->num_pds >= MAX_INTS) {
			WARN("In refresh_sniffers_list() have reached max number of interfaces\n");
			// TO DO: handle this situation better
			continue;
		}
		memcpy(&sn->sn[sn->num_pds].intf, &temp_intf[j], sizeof(interface_t));
		int res = setup_pd(&sn->sn[sn->num_pds].intf, &sn->sn[sn->num_pds].pd, filter_exp, sn->use_pktap);
		if ((res < 0)||(sn->sn[sn->num_pds].pd==NULL)) {
			WARN("Problem creating sniffer for interface %s\n",sn->sn[sn->num_pds].intf.name);
			continue;
		}
		sn->sn[sn->num_pds].offset = get_DLT_offset(sn->sn[sn->num_pds].pd, sn->use_pktap);
		if (sn->sn[sn->num_pds].offset<0) {
			WARN("Problem getting datalink offset for interface %s\n",sn->sn[sn->num_pds].intf.name);
			pcap_close(sn->sn[sn->num_pds].pd);
			continue;
		}
		sn->sn[sn->num_pds].datalink = pcap_datalink(sn->sn[sn->num_pds].pd);
		sn->sn[sn->num_pds].fd = pcap_get_selectable_fd(sn->sn[sn->num_pds].pd);
		if (!quiet) {
			if (!extra) {printf("added interface "); extra=1;} else printf(", ");
			printf("%s (dlt %d)", sn->sn[sn->num_pds].intf.name,sn->sn[sn->num_pds].datalink);
		}
		sn->num_pds++;
	}
	if (extra && !quiet) printf("\n");
	for (int i = 0; i<old_sn.num_pds; i++) {
		if (old_sn.sn[i].pd!=NULL) pcap_close(old_sn.sn[i].pd); // tidy up dead sniffers
	}
	/*struct timeval end; gettimeofday(&end, NULL);
	printf("refresh_sniffers_list() t=%f",(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);*/
	return sn->num_pds;
}

void sniffer_callback(u_char* raw_args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// send pkt to GUI.
	if (!are_sniffing) return;
	
	sniffer_callback_args_t args = *((sniffer_callback_args_t*)raw_args);
	int pkt_pid=-1; char *name=NULL;
	
	if (args.sn->use_pktap) {
		// we need to get offset from the PKTAP header itself
		struct pktap_header *hdr = (struct pktap_header *)pkt;
		if (hdr->pth_type_next == 0) {
			// no packet follows header
			WARN("No packet after PKTAP header (pid=%d)\n",pkt_pid);
			return;
		}
		
		pkt_pid = hdr->pth_pid;
		char buf[MAXCOMLEN];
		// make sure we have a NUL terminated string ...
		strlcpy(buf,hdr->pth_comm,MAXCOMLEN);
		name = trimwhitespace(buf); // seems like this is needed !
		if ((pkt_pid <=0) || (strnlen(name,MAXCOMLEN)==0)) {
			// this happens with IGMP and broadcasts
			return;
		}

		// step past the next header (likely ethernet)
		args.sn->sn[args.i].offset = hdr->pth_length;
		int offset=get_DLT_offset2(hdr->pth_dlt);
		if (offset<0) {
			WARN("Problem getting datalink offset for interface %s\n",args.sn->sn[args.i].intf.name);
			return; // its a serious error, we should probably close down sniffing
		}
		args.sn->sn[args.i].offset += offset;
	}

	//printf("sniffed pkt on interface %s(%d, datalink %d, offset %d, fd=%d), sending to GUI ... %d bytes\n", args.sn->interfaces[args.i], args.i, args.sn->datalink[args.i], args.sn->offset[args.i], pcap_get_selectable_fd(args.sn->pds[args.i]), pkthdr->caplen);
	const u_char* pkt_proper = pkt + args.sn->sn[args.i].offset; // look past link layer header to pkt itself
	size_t pkt_proper_len = pkthdr->caplen - args.sn->sn[args.i].offset;
	
	int version = (*pkt_proper)>>4; // get IP version
	int proto;
	u_char* nexth=NULL; // this will point to TCP/UDP header
	if (version == 4) {
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)pkt_proper;
		proto=ip->ip_p;
		nexth=((u_char *)ip + (ip->ip_hl * 4));
	} else {
		struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)pkt_proper;
		proto=ip->ip_nh;
		nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
	}
	
	// filtering doesn't seem to work right with tap header, sigh,
	// so we do it here
	if (proto == IPPROTO_TCP) {
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
		int syn = (tcp->th_flags & (TH_SYN)) && !(tcp->th_flags & (TH_ACK));
		int synack = (tcp->th_flags & (TH_SYN)) && (tcp->th_flags & (TH_ACK));
		if (args.sn->use_pktap) {
			// with PKTAP we only pass syn-acks on to client
			if (!synack) return;
		} else {
			// if not using PKTAP then when
			// dtrace is running on receipt of a syn we signal to
			// dtrace to look for connect() trace info, otherwise
			// we pass the syn on to client.
			if ( dtrace_active() && syn) { signal_dtrace(); return; }
		}
	} else if (proto == IPPROTO_UDP) {
		struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)nexth;
		uint16_t sport=ntohs(udp->uh_sport);
		uint16_t dport=ntohs(udp->uh_dport);
		int filt = (sport==443) || (dport==443) || (sport==53) || (dport==53) || (sport==5353) || (dport==5353);
		if (args.sn->use_pktap && !filt) return;
	} else {
		// not TCP or UDP
		return;
	}
	
	// before sending data, we recheck client when PID changes
	int current_pid = get_sock_pid(p_sock2, PCAP_PORT);
	if (current_pid != pid) {
		if (check_signature(p_sock2, PCAP_PORT)<0) goto err;
	}
	pid = current_pid;
	
	if (p_sock2<0) {WARN("pcap send p_sock2<0\n"); goto stop; } // socket is closed, bail
	if (send(p_sock2, pkthdr, sizeof(struct pcap_pkthdr),0)<0) goto err;
	if (send(p_sock2, &pkt_pid, sizeof(int),0)<0) goto err;
	ssize_t len=0;
	if (name != NULL) len = strnlen(name, MAXCOMLEN);
	if (send(p_sock2, &len, sizeof(ssize_t),0)<0) goto err;
	if (len>0) {if (send(p_sock2, name, len,0)<0) goto err;}
	if (send(p_sock2, &pkt_proper_len, sizeof(size_t),0)<0) goto err;
	if (send(p_sock2, pkt_proper, pkt_proper_len,0)<0) goto err;
	
	// periodically log pcap stats ... we don't want to be seeing too many pkt drops
	time_t stats_now = time(NULL);
	if (stats_now-stats_time > 600) {
		struct pcap_stat stats;
		stats_time = stats_now;
		pcap_stats(args.sn->sn[args.i].pd, &stats);
		INFO("pcap stats for intf %s (%d): recvd=%d, dropped=%d, if_dropped=%d\n",args.sn->sn[args.i].intf.name,args.i,
		stats.ps_recv,stats.ps_drop,stats.ps_ifdrop);
		fflush(stdout);
	}
	return;
	
err:
	WARN("pcap send: %s\n", strerror(errno));
stop:
	// likely helper has shut down connection,
	// in any case exit all of the pcap listening loops.
	// alternatively we could just exit this pcap sniffer
	// and leave others active, but if they sniff no pkts then
	// they may never exit even if p_sock2 is closed, so seems
	// safer to exit them all when one fails, even though it will
	// be flagged as a serious fault by GUI client if the client itself
	// didn't close the connection.
	are_sniffing = 0; // flag sniffer_loop() to stop. 
}

void sniffer_loop(pcap_handler callback, int *running, char* tag, char* filter_exp, sniffers_t *sn, int use_pktap)  {
	// pcap sniffer loop,this will exit when network connection fails/is broken.
	sniffers_t sn_local;
	if (sn == NULL) sn=&sn_local;
	memset(sn,0,sizeof(sniffers_t));
	sn->use_pktap = use_pktap;
	sniffer_callback_args_t args[MAX_INTS];
	for (int i = 0; i<MAX_INTS; i++) {args[i].sn = sn; args[i].i=i; }
	INFO("Starting %s sniffers (use_pktap=%d)\n", tag, use_pktap);
	refresh_sniffers_list(sn, filter_exp,0);
	INFO("%s sniffing on interface(s): ", tag);
	for (int i=0; i<sn->num_pds; i++) {
		printf("%s ",sn->sn[i].intf.name);
	}
	printf("\n");
	//*running = 1;
	while(*running) {
		refresh_sniffers_list(sn, filter_exp,0); // this call is quite cheap
		struct timeval timeout;
		timeout.tv_sec = SNIFFER_LOOP_TIMEOUT; timeout.tv_usec = 0; // timeout for select()
		fd_set readfds; FD_ZERO(&readfds);
		int maxfd = 0;
		for (int i=0; i<sn->num_pds; i++) {
			if (sn->sn[i].fd>maxfd) maxfd = sn->sn[i].fd;
			FD_SET(sn->sn[i].fd,&readfds);
			pcap_setnonblock(sn->sn[i].pd,1,NULL);
		}
		// nb: we won't block here indefinitely due to the timeout.  that way if a new
		// interface comes up we'll definitely start to monitor it (otherwise without timeout
		// we might block here indefinitely and never add new interface to select()).
		// can also use signal() to break out of select() early if needed.
		int res = select(maxfd+1, &readfds, NULL, NULL, &timeout);
		if (res<0) { // res=0 on timeout, <0 on error
			if (errno == EINTR) { // signal interrupted select(), its normal
				//printf("select() signal %d\n", *running);
			} else {
				WARN("%s sniffer loop select: %s (res=%d)\n", tag, strerror(errno), res);
			}
			continue;
		}
		for (int i=0; i<sn->num_pds; i++) {
			if (FD_ISSET(sn->sn[i].fd,&readfds)) {
				
				int n=pcap_dispatch(sn->sn[i].pd, -1,	callback, (u_char*)&args[i]);
				if (n == PCAP_ERROR) ERR("%s sniffer loop pcap_dispatch: %s\n", tag, pcap_geterr(sn->sn[i].pd));
				//printf("got %d pkts for %d\n",n,i);
			}
			if (!*running) break;  
		}
	}
	INFO2("Exited %s sniffer loop.\n", tag);
	//tidy up
	for (int i=0; i<sn->num_pds; i++) {
		if (sn->sn[i].pd) pcap_close(sn->sn[i].pd);
		sn->sn[i].pd = NULL;
	}

}

void *listener(void *ptr) {
	// wait in accept() loop to handle connections from GUI to receive pcap info
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d (pcap) ...\n", PCAP_PORT);
		if ((p_sock2 = accept(p_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			ERR("Problem accepting new connection on localhost port %d (pcap): %s\n", PCAP_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d (pcap)\n", PCAP_PORT);
		// GUI expects this connection to be kept open unless there is a
		// signing issue or a major error with appFirewall-Helper.
		// so even if no interfaces are up, we take the connection
		// and sit and wait.
		if (check_signature(p_sock2, PCAP_PORT)<=0) {
			// couldn't authenticate client
			close(p_sock2);
			continue;
		}
		pid = get_sock_pid(p_sock2, PCAP_PORT);
		
		set_snd_timeout(p_sock2, SND_TIMEOUT); // to be safe, send() will eventually timeout

		stats_time = time(NULL);
		// start up a sniffer for each interface.
		if (get_interfaces(NULL, USE_PKTAP) == 0) {
			// no interfaces are up, sit here and wait.
			// polling loop here is easy but seems a bit clunky ...
			INFO("No interfaces up, pcap loop waiting ...\n");
			while (get_interfaces(NULL, USE_PKTAP)==0) {
				sleep(1);
			}
			INFO("Interfaces up, pcap loop continuing.\n");
		}
		are_sniffing = 1;
		sniffer_loop(sniffer_callback, &are_sniffing, "pcap", filter_exp, NULL, USE_PKTAP);
		close(p_sock2);
	}
	return NULL;
}

void start_listener() {
	// start listening for requests to receive pcap info
	p_sock = bind_to_port(PCAP_PORT,2);
	INFO("Now listening on localhost port %d (%s)\n", PCAP_PORT, pcap_lib_version());
	pthread_create(&listener_thread, NULL, listener, NULL);
}

