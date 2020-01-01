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

int get_interfaces(char intf[MAX_INTS][STR_SIZE]) {
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
  
  // we add a listener to every IPv4/IPv6 interface
	struct ifaddrs *ifap;
	if (getifaddrs(&ifap)<0) {
		ERR("Couldn't get list of interfaces from getifaddrs() for pcap sniffer: %s", strerror(errno));
		// should this be fatal ?
		return -1;
	}
	struct ifaddrs *dev;
	int count=0;
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
		struct sockaddr *addr = dev->ifa_addr;
		char addr_name[INET6_ADDRSTRLEN];
		if (addr->sa_family == AF_INET) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
		} else if (addr->sa_family == AF_INET6) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in6*)addr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
		} else {DEBUG2("not IPv4/IPv6\n"); continue;}
		char* mask6="fe80:", *mask4="169.254";
		if ((strncmp(mask6, addr_name, strnlen(mask6,STR_SIZE)) == 0)
				|| (strncmp(mask4, addr_name, strnlen(mask4,STR_SIZE)) == 0)) {
			DEBUG2("link local addr\n");
			continue; // ignore link local addresses
		}
		DEBUG2("addr %s found\n",addr_name);
		if (intf!=NULL) strlcpy(intf[count],dev->ifa_name,STR_SIZE);
		DEBUG2("valid interface: %s\n", intf[count]);
		if (count < MAX_INTS) {
			count++;
		} else {
			WARN("get_interfaces() >%d interfaces found\n", MAX_INTS);
			break;
		}
	}
	freeifaddrs(ifap);
	//}
	return count;
}

int get_DLT_offset(pcap_t *pd) {

	int datalink, offset=0;
  if ((datalink = pcap_datalink(pd)) < 0){
    WARN("Cannot obtain datalink information: %s", pcap_geterr(pd));
    return -1;
	}

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
		default:
			ERR("Unknown datalink type: %d\n", datalink);
			return -1;
		}
		return offset;
}

int setup_pd(char* intf, pcap_t **pd, char* filter_exp) {
	// initialise a pcap listener for an available interfaces
	char ebuf[PCAP_ERRBUF_SIZE];

	// create pcap listener
	if ((*pd = pcap_create(intf, ebuf)) == NULL) {
		ERR("Couldn't create pcap sniffer %s\n",ebuf);
		return -1;
	}

	#define SNAPLEN 512 // needs to be big enough to capture dns payload
	if (pcap_set_snaplen(*pd,SNAPLEN)!=0) {
		WARN("Couldn't set snaplen on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	if (pcap_set_immediate_mode(*pd,1)!=0) { // deliver sniffed packets immediately.
		WARN("Couldn't set immediate mode on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	#define BUFFER_SIZE 2097152*8  // default is 2M=2097152, but we increase it to 16M
	pcap_set_buffer_size(*pd, BUFFER_SIZE);
	
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

	struct bpf_program fp;
	if (pcap_compile(*pd, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
		ERR("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
		return -1;
	}
	if (pcap_setfilter(*pd, &fp) == PCAP_ERROR) {
		ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
		return -1;
	}
	return 1;
}

int refresh_sniffers_list(sniffers_t* sn, char* filter_exp) {
	// get an update on the available interfaces ...
	//struct timeval start; gettimeofday(&start, NULL);
	char temp_interfaces[MAX_INTS][STR_SIZE];
	int n=0;
	sniffers_t old_sn;
	memcpy(&old_sn,sn,sizeof(sniffers_t));
	memset(sn,0,sizeof(sniffers_t));
	if ( (n=get_interfaces(temp_interfaces))<=0) {
		return 0;
	}
	int i;
	for (int j=0; j<n; j++) {
		for (i = 0; i<old_sn.num_pds; i++) {
			if (strcmp(old_sn.interfaces[i], temp_interfaces[j])==0) break;
		}
		if (i<old_sn.num_pds) {
			// interface already has an existing sniffer
			sn->pds[sn->num_pds] = old_sn.pds[i];
			strlcpy(sn->interfaces[sn->num_pds],old_sn.interfaces[i], STR_SIZE);
			sn->fd[sn->num_pds] = old_sn.fd[i];
			sn->datalink[sn->num_pds] = old_sn.datalink[i];
			sn->offset[sn->num_pds] = old_sn.offset[i];
			sn->num_pds++;
			old_sn.pds[i] = NULL; // mark as copied
			continue;
		}
		// a new interface has appeared
		if (sn->num_pds >= MAX_INTS) {
			WARN("In refresh_sniffers_list() have reached max number of interfaces\n");
			// TO DO: handle this situation better
			continue;
		}
		strlcpy(sn->interfaces[sn->num_pds],temp_interfaces[j],STR_SIZE);
		int res = setup_pd(sn->interfaces[sn->num_pds], &sn->pds[sn->num_pds], filter_exp);
		if ((res < 0)||(sn->pds[sn->num_pds]==NULL)) {
			WARN("Problem creating sniffer for interface %s\n",sn->interfaces[sn->num_pds]);
			continue;
		}
		sn->offset[sn->num_pds] = get_DLT_offset(sn->pds[sn->num_pds]);
		if (sn->offset[sn->num_pds]<0) {
			WARN("Problem getting datalink offset for interface %s\n",sn->interfaces[sn->num_pds]);
			pcap_close(sn->pds[sn->num_pds]);
			continue;
		}
		sn->datalink[sn->num_pds] = pcap_datalink(sn->pds[sn->num_pds]);
		sn->fd[sn->num_pds] = pcap_get_selectable_fd(sn->pds[sn->num_pds]);
		sn->num_pds++;
	}
	for (int i = 0; i<old_sn.num_pds; i++) {
		if (old_sn.pds[i]!=NULL) pcap_close(old_sn.pds[i]); // tidy up dead sniffers
	}
	/*struct timeval end; gettimeofday(&end, NULL);
	printf("refresh_sniffers_list() t=%f",(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);*/

	return sn->num_pds;
}

void sniffer_callback(u_char* raw_args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// send pkt to GUI.
	sniffer_callback_args_t args = *((sniffer_callback_args_t*)raw_args);
	DEBUG2("sniffed pkt on interface %s(%d, datalink %d, offset %d, fd=%d), sending to GUI ... %d bytes\n", args.sn->interfaces[args.i], args.i, args.sn->datalink[args.i], args.sn->offset[args.i], pcap_get_selectable_fd(args.sn->pds[args.i]), pkthdr->caplen);
	const u_char* pkt_proper = pkt + args.sn->offset[args.i]; // look past link layer header to pkt itself
	size_t pkt_proper_len = pkthdr->caplen - args.sn->offset[args.i];
	
	if (dtrace_active()) {
		// when dtrace is running on receipt of a syn we signal to
		// dtrace to look for connect() trace info, otherwise
		// we pass the syn on to client.
		int version = (*pkt_proper)>>4; // get IP version
		//int proto;
		u_char* nexth=NULL; // this will point to TCP/UDP header
		if (version == 4) {
			struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)pkt_proper;
			//proto=ip->ip_p;
			nexth=((u_char *)ip + (ip->ip_hl * 4));
		} else {
			struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)pkt_proper;
			//proto=ip->ip_nh;
			nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
		}
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
		int syn = (tcp->th_flags & (TH_SYN)) && !(tcp->th_flags & (TH_ACK));
		if (syn) { signal_dtrace(); return; }
	}
	// before sending data, we recheck client when PID changes
	int current_pid = get_sock_pid(p_sock2, PCAP_PORT);
	if (current_pid != pid) {
		if (check_signature(p_sock2, PCAP_PORT)<0) goto err;
	}
	pid = current_pid;
	
	if (p_sock2<0) {WARN("pcap sned p_sock2<0\n"); goto stop; } // socket is closed, bail
	if (send(p_sock2, pkthdr, sizeof(struct pcap_pkthdr),0)<0) goto err;
	if (send(p_sock2, &args.sn->datalink[args.i], sizeof(int),0)<0) goto err;
	if (send(p_sock2, &pkt_proper_len, sizeof(size_t),0)<0) goto err;
	if (send(p_sock2, pkt_proper, pkt_proper_len,0)<0) goto err;
	
	// periodically log pcap stats ... we don't want to be seeing too many pkt drops
	time_t stats_now = time(NULL);
	if (stats_now-stats_time > 600) {
		struct pcap_stat stats;
		stats_time = stats_now;
		pcap_stats(args.sn->pds[args.i], &stats);
		INFO("pcap stats for intf %s (%d): recvd=%d, dropped=%d, if_dropped=%d\n",args.sn->interfaces[args.i],args.i,
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
	are_sniffing = 0; // flag sniffer_loop() to stop
	pcap_breakloop(args.sn->pds[args.i]);
}

void sniffer_loop(pcap_handler callback, int *running, char* tag, char* filter_exp)  {
	// pcap sniffer loop,this will exit when network connection fails/is broken.
	sniffers_t sn; memset(&sn,0,sizeof(sn));
	sniffer_callback_args_t args[MAX_INTS];
	for (int i = 0; i<MAX_INTS; i++) {args[i].sn = &sn; args[i].i=i; }
	INFO("Starting %s sniffers on: ", tag);
	refresh_sniffers_list(&sn, filter_exp);
	for (int i=0; i<sn.num_pds; i++) {
		printf("%s ",sn.interfaces[i]);
	}
	printf("\n");
	*running = 1;
	while(*running) {
		refresh_sniffers_list(&sn, filter_exp); // this call is quite cheap
		struct timeval timeout;
		timeout.tv_sec = SNIFFER_LOOP_TIMEOUT; timeout.tv_usec = 0; // timeout for select()
		fd_set readfds; FD_ZERO(&readfds);
		int maxfd = 0;
		for (int i=0; i<sn.num_pds; i++) {
			if (sn.fd[i]>maxfd) maxfd = sn.fd[i];
			FD_SET(sn.fd[i],&readfds);
			pcap_setnonblock(sn.pds[i],1,NULL);
		}
		// nb: we won't block here indefinitely due to the timeout.  that way if a new
		// interface comes up we'll definitely start to monitor it (otherwise without timeout
		// we might block here indefinitely and never add new interface to select()).
		// can also use signal() to break out of select() early if needed.
		int res = select(maxfd+1, &readfds, NULL, NULL, &timeout);
		if (res == EINTR) continue; // signal interrupted select()
		if (res<0) { // res=0 on timeout, <0 on error
			WARN("%s sniffer loop select: %s (res=%d)", tag, strerror(errno), res);
			continue;
		}
		for (int i=0; i<sn.num_pds; i++) {
			if (FD_ISSET(sn.fd[i],&readfds)) {
				
				int n=pcap_dispatch(sn.pds[i], -1,	callback, (u_char*)&args[i]);
				if (n == PCAP_ERROR) ERR("%s sniffer loop pcap_dispatch: %s\n", tag, pcap_geterr(sn.pds[i]));
				//printf("got %d pkts for %d\n",n,i);
			}
			if (!*running) break;  // don't both with lock, doesn't matter if this fails
		}
	}
	INFO2("Exited %s sniffer loop.\n", tag);
	//tidy up
	for (int i=0; i<sn.num_pds; i++) {
		if (sn.pds[i]) pcap_close(sn.pds[i]);
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
		if (get_interfaces(NULL) == 0) {
			// no interfaces are up, sit here and wait.
			// polling loop here is easy but seems a bit clunky ...
			INFO("No interfaces up, pcap loop waiting ...\n");
			while (get_interfaces(NULL)==0) {
				sleep(1);
			}
			INFO("Interfaces up, pcap loop continuing.\n");
		}
		sniffer_loop(sniffer_callback, &are_sniffing, "pcap", filter_exp);
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

