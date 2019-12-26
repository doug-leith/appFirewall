//
//  pcap_sniffer.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "pcap_sniffer.h"

//globals
static sniffers_t sn = SNIFFERS_INITIALIZER;
static time_t stats_time; // time when last asked pcap for stats
static int p_sock, p_sock2=-1;
static pthread_mutex_t pcap_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
static int pid = -1;
static pthread_t listener_thread; // handle to listener thread
static pthread_t interface_watcher_thread;
static pthread_mutex_t watcher_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
static pthread_cond_t watcher_cond = PTHREAD_COND_INITIALIZER;
static int wakeup = 0;

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

char** get_interfaces() {
	// get list of useful interfaces (IPv4 or IPv6 and not link-local,
	// might be down but that's ok)
	char **intf = calloc(MAX_INTS,sizeof(char*));
		
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
		return intf;
	}
	struct ifaddrs *dev;
	int count=0;
	for(dev=ifap; dev; dev=dev->ifa_next) {
		DEBUG2("interface %s ...",dev->ifa_name);
		if (dev-> ifa_flags & IFF_LOOPBACK) {DEBUG2("loopback\n"); continue;}
		if (dev-> ifa_flags & IFF_POINTOPOINT) {DEBUG2("point to point\n"); continue;}
		if (dev->ifa_flags&IFF_NOARP) {DEBUG2("no ARP\n"); continue;}
		if ((dev->ifa_flags&IFF_UP)==0) {DEBUG2("point to point\n"); continue;}
		if ((dev->ifa_flags&IFF_BROADCAST)==0) {DEBUG2("no valid broadcast addr\n"); continue;}
		//if (!dev->ifa_netmask) {printf("no valid netmask\n"); continue;}
		struct sockaddr *addr = dev->ifa_addr;
		char addr_name[INET6_ADDRSTRLEN];
		if (addr->sa_family == AF_INET) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, addr_name, INET6_ADDRSTRLEN);
		} else if (addr->sa_family == AF_INET6) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in6*)addr)->sin6_addr, addr_name, INET6_ADDRSTRLEN);
		} else {DEBUG2("not IPv4/IPv6\n"); continue;}
		char* mask="fe80:";
		if (strncmp(mask, addr_name, strlen(mask)) == 0) {
			DEBUG2("link local addr\n");
			continue; // ignore IPv6 link local addresses
		}
		DEBUG2("addr %s found\n",addr_name);
		intf[count] = malloc(STR_SIZE*sizeof(char));
		strlcpy(intf[count],dev->ifa_name,STR_SIZE);
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
	return intf;
}

int setup_pd(char* intf, pcap_t **pd) {
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
	if (pcap_activate(*pd)!=0) {
		ERR("Couldn't activate pcap sniffer: %s\n",pcap_geterr(*pd));
		return -1;
	}
			
	// we need to specify the link layer header size.  have hard-wired in
	// ethernet value of 14, so check link we have is compatible with this
	int dl;
	if ( (dl=pcap_datalink(*pd)) != DLT_EN10MB) { //
		ERR("Pcap device %s not supported: %d\n", intf, dl);
		return -1;
	}
	return 1;
}

void free_sniffers(sniffers_t* sn) {
	for (int i = 0; i< sn->num_pds; i++) {
		if (sn->interfaces[i]) free(sn->interfaces[i]);
		if (sn->pds[i]) pcap_close(sn->pds[i]);
	}
	memset(sn,0,sizeof(sniffers_t));
}

int refresh_sniffers_list(sniffers_t* sn) {
	// get an update on the available interfaces ...
	//struct timeval start; gettimeofday(&start, NULL);
	char** temp_interfaces = get_interfaces();
	
	// if any new interfaces added, we add a new sniffer.
	// nb: we leave existing sniffers untouched, even if their
	// interface has gone down/away, otherwise join loop in
	// listener thread might get messed up
	
	int i;
	for (char** intf = temp_interfaces; *intf; intf++) {
		for (i = 0; i<sn->num_pds; i++) {
			if (strcmp(sn->interfaces[i], *intf)==0) break;
		}
		if (i<sn->num_pds) {
			// interface already has an existing sniffer
			free(*intf);
			continue;
		}
		// a new interface has appeared
		if (sn->num_pds >= MAX_INTS) {
			WARN("in refresh_sniffers_list() have reached max number of interfaces\n");
			free(*intf);
			continue;
		}
		sn->interfaces[sn->num_pds] = *intf;
		/*char ebuf[PCAP_ERRBUF_SIZE];
		if (pcap_lookupnet(*intf, &sn->net[sn->num_pds], &sn->mask[sn->num_pds], ebuf) == -1) {
			WARN("Can't get netmask for interface %s: %s\n", *intf, ebuf);
			sn->net[sn->num_pds] = 0;
			sn->mask[sn->num_pds] = 0;
		}*/
		int res = setup_pd(*intf, &sn->pds[sn->num_pds]);
		if (res < 0) {
			WARN("Problem creating sniffer for interface %s\n",*intf);
			free(*intf);
			continue;
		}
		sn->needs_thread[sn->num_pds] = 1;
		sn->num_pds++;
	}
	free(temp_interfaces);
	
	//struct timeval end; gettimeofday(&end, NULL);
	//printf("refresh_sniffers_list() t=%f",(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);

	return sn->num_pds;
}

void sigusr1_handler(int signum) {
	printf("signal %d received (SIGUSR1=%d), exiting sniffer thread.\n", signum, SIGUSR1);
	pthread_exit(NULL);
}

void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// send pkt to GUI
	int i = *((int*)args);
	DEBUG2("sniffed pkt on interface %s(%d), sending to GUI ... %d bytes\n", sn.interfaces[i], i, pkthdr->caplen);
	
	if (dtrace_active()) {
		// when dtrace is running on receipt of a syn we signal to
		// dtrace to look for connect() trace info, otherwise
		// we pass the syn on to client.
		const int pcap_off = 14; // ethernet link layer offset
		int version = (*(pkt + pcap_off))>>4; // get IP version
		u_char* nexth=NULL; // this will point to TCP/UDP header
		if (version == 4) {
			struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(pkt + pcap_off);
			nexth=((u_char *)ip + (ip->ip_hl * 4));
		} else {
			struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)(pkt + pcap_off);
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
	
	// take a lock on p_sock2 so that messages from different
	// threads don't get interleaved.  could use datagram/packet
	// socket instead to achieve this (probably nicer).
	pthread_mutex_lock(&pcap_mutex);
	if (p_sock2<0) goto stop; // socket is closed, bail
	if (send(p_sock2, pkthdr, sizeof(struct pcap_pkthdr),0)<0) goto err;
	if (send(p_sock2, pkt, pkthdr->caplen,0)<0) goto err;
	pthread_mutex_lock(&pcap_mutex);
	
	// periodically log pcap stats ... we don't want to be seeing too many pkt drops
	time_t stats_now = time(NULL);
	if (stats_now-stats_time > 600) {
		struct pcap_stat stats;
		stats_time = stats_now;
		pcap_stats(sn.pds[i], &stats);
		INFO("pcap stats for intf %s (%d): recvd=%d, dropped=%d, if_dropped=%d\n",sn.interfaces[i],i,
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
	pthread_mutex_unlock(&pcap_mutex);
	pthread_mutex_lock(&sn.sniffer_mutex);
	for (int j=0; j<sn.num_pds; j++) {
		pthread_kill(sn.sniffer_threads[j],SIGUSR1);
		//pcap_breakloop() doesn't work across threads, we need to use a signal.
		//pcap_breakloop(sn.pds[j]);
	}
	sn.is_sniffing = 0; // stop interface watcher starting up new threads
	pthread_mutex_unlock(&sn.sniffer_mutex);
}

void *sniffer(void *arg)  {
	// fire up pcap loop,this will exit when network connection fails/is broken.
	// no need to take lock here as watcher only ever adds to pd list
	int i = *((int*)arg);
	struct bpf_program fp;		// the compiled filter expression
	bpf_u_int32 mask = 0;
	if (pcap_compile(sn.pds[i], &fp, filter_exp, 0, mask) == -1) {
		ERR("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(sn.pds[i]));
		return NULL;
	}
	if (pcap_setfilter(sn.pds[i], &fp) == -1) {
		ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(sn.pds[i]));
		return NULL;
	}
	// setup handler to exit thread on SIGUSR1 signal, use this to break out of
	// pcap_loop()
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = sigusr1_handler;
	sigaction(SIGUSR1, &action, NULL);
	// enter sniffer loop
	if (pcap_loop(sn.pds[i], -1,	sniffer_callback, (u_char*)&i)==PCAP_ERROR){	// this blocks
		ERR("sniffer pcap_loop: %s\n", pcap_geterr(sn.pds[i]));
	}
	return NULL;
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
		// take lock to stop watcher changing sn.num_pds
		pthread_mutex_lock(&sn.sniffer_mutex);
		sn.is_sniffing = 1;
		int int_num[MAX_INTS];
		refresh_sniffers_list(&sn);
		if (sn.num_pds>0) {
			INFO("Starting pcap sniffers: ");
			for (int i = 0; i<sn.num_pds; i++) {
				printf("%s ", sn.interfaces[i]);
				int_num[i] = i;
				pthread_create(&sn.sniffer_threads[i], NULL, sniffer, &int_num);
				sn.needs_thread[i]=0;
			}
			printf("\n");
			pthread_mutex_unlock(&sn.sniffer_mutex);
		} else {
			// no interfaces are up, sit here and wait -- interface_watcher
			// thread will keep an eye out for changes in interface status.
			// nb: if interfaces go down once threads are started it ok,
			// pcap keeps listening and reactivates when the interface
			// comes back up, so will only exit join upon an error in one
			// of the threads -- only likely cause of this is GUI client
			// closing connection i.e. going away.
			// polling loop here is easy but seems a bit clunky ...
			INFO("No interfaces up, pcap loop waiting ...\n");
			while (sn.num_pds==0) {
				pthread_mutex_unlock(&sn.sniffer_mutex);
				sleep(1);
				pthread_mutex_lock(&sn.sniffer_mutex);
			}
			pthread_mutex_unlock(&sn.sniffer_mutex);
			INFO("Interfaces up, pcap loop continuing to join\n");
		}
		// and now wait here until all the sniffers finish.
		// nb: interface_watcher thread only adds to our list of sniffers,
		// it never deletes, so this join loop is safe.
		pthread_mutex_lock(&sn.sniffer_mutex);
		for (int i = 0; i<sn.num_pds; i++) {
			pthread_mutex_unlock(&sn.sniffer_mutex);
			pthread_join(sn.sniffer_threads[i], NULL);
			pthread_mutex_lock(&sn.sniffer_mutex);
		}
		sn.is_sniffing = 0; // stop watcher starting new threads
		free_sniffers(&sn);
		pthread_mutex_unlock(&sn.sniffer_mutex);
		close(p_sock2);
	}
	return NULL;
}

void *interface_watcher(void *ptr) {
	int prev_num_pds=0;
	for(;;) {
		// check for changes to the set of available interfaces
		// (wifi has come up, a usb adapter might have been
		// added/removed, a VPN tun might have been added/removed etc)
		// we leave already running sniffers alone, as ok if
		// interface is down, but start new threads as needed.

		// take lock as refresh_sniffers_list() might change sn.num_pds
		pthread_mutex_lock(&sn.sniffer_mutex);
		if (sn.is_sniffing) { // active just now
			refresh_sniffers_list(&sn);
			if (sn.num_pds != prev_num_pds) INFO("interface watcher: ");
			// start up a sniffer for any new interfaces
			if (sn.num_pds == 0) {
				if (sn.num_pds != prev_num_pds) printf("no interfaces");
			}
			int int_num[MAX_INTS];
			for (int i = 0; i<sn.num_pds; i++) {
				if (sn.num_pds != prev_num_pds) printf("%s ", sn.interfaces[i]);
				if (!sn.needs_thread[i]) continue;
				if (sn.num_pds != prev_num_pds) printf("(new) ");
				int_num[i] = i;
				pthread_create(&sn.sniffer_threads[i], NULL, sniffer, &int_num);
				sn.needs_thread[i] = 0;
			}
			if (sn.num_pds != prev_num_pds) printf("\n");
			prev_num_pds = sn.num_pds;
		}
		pthread_mutex_unlock(&sn.sniffer_mutex);
		// we poll interface state as doesn't seem to be any nicer way
		// to do it (no kqueue API on macos for network devices).
		struct timespec t;
		clock_gettime(CLOCK_REALTIME, &t);
		t.tv_sec += PCAP_REFRESH_INTERVAL;
		pthread_mutex_lock(&watcher_mutex);
		int res = 0;
		while ((wakeup==0) && (res != ETIMEDOUT)) {
			res = pthread_cond_timedwait(&watcher_cond, &watcher_mutex, &t);
			if ((res!=0) && (res!=ETIMEDOUT)) {
				WARN("interface_watcher() cond error: %s", strerror(errno));
			}
		}
		wakeup = 0;
		pthread_mutex_unlock(&watcher_mutex);
		//sleep(PCAP_REFRESH_INTERVAL);
	}
}

void signal_interface_watcher() {
	// ask watcher to refresh pid_list
	pthread_mutex_lock(&watcher_mutex);
	wakeup = 1;
	pthread_cond_signal(&watcher_cond);
	pthread_mutex_unlock(&watcher_mutex);
	//printf("signalled watcher\n");
}

void start_listener() {
	sn.is_sniffing = 0; // initialise to idle state
	// watch available interfaces and maintain list of
	// sniffers
	pthread_create(&interface_watcher_thread, NULL, interface_watcher, NULL);
	INFO("Interface watcher started\n");
	// start listening for requests to receive pcap info
	p_sock = bind_to_port(PCAP_PORT,2);
	INFO("Now listening on localhost port %d (pcap)\n", PCAP_PORT);
	pthread_create(&listener_thread, NULL, listener, NULL);
}

void stop_listener() {
	pthread_kill(interface_watcher_thread, SIGTERM);
	pthread_kill(listener_thread, SIGTERM);
}
