//
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

// TCP header details: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_timestamps
// libnet tutorials: https://repolinux.wordpress.com/2011/09/18/libnet-1-1-tutorial/#receiving-packets
//https://repolinux.wordpress.com/category/libnet/#sending-multiple-packets
// libnet source: https://github.com/libnet/libnet
// RFC on RST attack mitigations: https://tools.ietf.org/html/rfc5961#section-3.2
// nice blog post on TCP RST details: https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/

//source for tcp protocol block:
//https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netinet/tcp_var.h.auto.html


#include "catch_escapee.h"

//globals
static pthread_t catcher_thread; // handle to catcher thread
static pthread_t catcher_listener_thread; // handle to catcher_listener thread
static int c_sock, c_sock2=-1;
static int catcher_sniffing = 0;
static libnet_data_t ld, ld_prompt;
sniffers_t sn_esc;
char intf[STR_SIZE];
uint8_t eth[ETHER_ADDR_LEN];

typedef struct catcher_callback_args_t {
	int af;
	struct in6_addr target_dst;
	uint16_t target_sport, target_dport;
	int target_pid;
	int pkt_count;
} catcher_callback_args_t;
static catcher_callback_args_t a;

int find_fds(int pid, int af, struct in6_addr dst, uint16_t sport, uint16_t dport, conn_raw_t *cr) {
	// Figure out the size of the buffer needed to hold the list of open FDs
	int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (bufferSize == -1) {
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d (catch_escapee)\n", pid);
		return 0;
	}

	struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
	if (!procFDInfo) {
		ERR("Out of memory. Unable to allocate buffer with %d bytes (catch_escapee)\n", bufferSize);
		return -1;
	}
	
	if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d (catch_escapee)\n", pid);
		return 0;
	}
	int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
	
	for(int i = 0; i < numberOfProcFDs; i++) {
		conn_raw_t c; // the new connection
		memset(&c,0,sizeof(c));
		
		if (procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET)
			continue; // not a socket fd
		
		struct socket_fdinfo socketInfo;
		memset(&socketInfo,0,sizeof(socketInfo));
		int res = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
		if (res != sizeof(struct socket_fdinfo)) continue;
		
		//int state = socketInfo.psi.soi_proto.pri_tcp.tcpsi_state;
		if ((socketInfo.psi.soi_kind != SOCKINFO_TCP)) continue; // not TCP
		
		struct in_sockinfo* sockinfo = &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
		c.af=socketInfo.psi.soi_family;
		memset(&c.src_addr,0,sizeof(struct in6_addr));
		memset(&c.dst_addr,0,sizeof(struct in6_addr));
		if (sockinfo->insi_vflag==INI_IPV4) { // IPv4
			if (c.af !=AF_INET) c.af = AF_INET;
			memcpy(&c.src_addr, &sockinfo->insi_laddr.ina_46.i46a_addr4, sizeof(struct in_addr));
			memcpy(&c.dst_addr, &sockinfo->insi_faddr.ina_46.i46a_addr4, sizeof(struct in_addr));
		} else { // IPv6
			if (c.af !=AF_INET6) c.af = AF_INET6;
			memcpy(&c.src_addr, &sockinfo->insi_laddr.ina_6, sizeof(struct in6_addr));
			memcpy(&c.dst_addr, &sockinfo->insi_faddr.ina_6, sizeof(struct in6_addr));
		}
		c.sport = ntohs(sockinfo->insi_lport);
		c.dport = ntohs(sockinfo->insi_fport);
		
		char src_addr_name[INET6_ADDRSTRLEN], dst_addr_name[INET6_ADDRSTRLEN];
		inet_ntop(c.af, &c.src_addr, src_addr_name, INET6_ADDRSTRLEN);
		inet_ntop(c.af, &c.dst_addr, dst_addr_name, INET6_ADDRSTRLEN);
		

		if (c.af != af) continue;
		if ((c.dport != dport) || (c.sport != sport)) continue;
		if (!are_addr_same(c.af, &c.dst_addr, &dst)) continue;
		*cr = c;
		free(procFDInfo);
		return 0;
	}

	free(procFDInfo);
	return -1;
}

void catcher_callback(u_char* raw_args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {

	if (!catcher_sniffing) return;
	
	// we got a pkt, let's process it ...
	// should take lock on a.pkt_count, but its just for stats
	// so ok if corrupted now and then

	sniffer_callback_args_t args = *((sniffer_callback_args_t*)raw_args);
	int pcap_off  = args.sn->sn[args.i].offset;

	struct timeval ts = pkthdr->ts;
	struct timeval start; gettimeofday(&start, NULL);
	double t=(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0;
	#define TIMEOUT 2 //packets >2s old are dropped, likely due to wakeup after sleep
	if (t > TIMEOUT) {
		INFO2("Received stale pkt, %f old. discard (catch_escapee)\n",t);
		return;
	}
	
	int version = (*(pkt + pcap_off))>>4; // get IP version
	int proto, af;
	struct in6_addr src, dst;
	memset(&src,0,sizeof(src)); memset(&dst,0,sizeof(dst));
	u_char* nexth=NULL; // this will point to TCP header
	if (version == 4) {
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(pkt + pcap_off);
		proto=ip->ip_p;
		af=AF_INET;
		memcpy(&src,&ip->ip_src,sizeof(struct in_addr));
		memcpy(&dst,&ip->ip_dst,sizeof(struct in_addr));
		nexth=((u_char *)ip + (ip->ip_hl * 4));
	} else {
		struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)(pkt + pcap_off);
		proto=ip->ip_nh;
		af=AF_INET6;
		memcpy(&src,&ip->ip_src,sizeof(struct in6_addr));
		memcpy(&dst,&ip->ip_dst,sizeof(struct in6_addr));
		nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
	}
	
	if (proto != IPPROTO_TCP) return; // shouldn't happen
	//if (!are_addr_same(af, &src, &a.target_dst) && !are_addr_same(af, &dst, &a.target_dst)) return;
	
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
	uint16_t sport=ntohs(tcp->th_sport);
	uint16_t dport=ntohs(tcp->th_dport);
	uint32_t seq=ntohl(tcp->th_seq);
	uint32_t ack=ntohl(tcp->th_ack);
	uint16_t win=ntohs(tcp->th_win);

	conn_raw_t cr;
	cr.af=af;
	int outgoing=0;
	if (dport == a.target_dport) {
		// outgoing packet
		outgoing=1;
		cr.src_addr=src; cr.dst_addr=dst;
		cr.sport=sport; cr.dport=dport;
		cr.seq=seq; cr.ack=ack;
	} else if (sport == a.target_dport) {
		// incoming packet
		cr.src_addr=dst; cr.dst_addr=src;
		cr.sport=dport; cr.dport=sport;
		cr.seq=ack; cr.ack=seq;
	} else {
		WARN("Received packet with mismatched ports, sport=%u/dport=%u but expected sport=%u/dport=%u (catch_escapee)\n", sport, dport, a.target_sport, a.target_dport);
		return;
	}
	if (cr.af == AF_INET6) {
		// for debugging
		char sn[INET6_ADDRSTRLEN],dn[INET6_ADDRSTRLEN];
		inet_ntop(cr.af, &cr.src_addr, sn, INET6_ADDRSTRLEN);
		inet_ntop(cr.af, &cr.dst_addr, dn, INET6_ADDRSTRLEN);
		printf("outgoing=%d %s:%d -> %s:%d seq=%u ack=%u win=%u, flags=%02x\n", outgoing,sn,cr.sport,dn,cr.dport, cr.seq, cr.ack, win, tcp->th_flags);
		//printf("intf=%s,  mac=",intf);
		//int i; for(i=0; i<ETHER_ADDR_LEN;i++) printf("%02x ",eth[i]); printf("\n");
	}
	if (tcp->th_flags & (TH_RST))  return; // let's not respond to our own RSTs
	
	a.pkt_count++; // record number of packets we've sniffed for this connection

	/* we're sending a RST on an established connection where likely soem data has already been sent.
	example of a RST after data sent:
	192.168.1.27	54.171.86.180	TCP	55248 → 2000 [SYN] Seq=3550827904 Len=0
	54.171.86.180	192.168.1.27	TCP 2000 → 55248 [SYN, ACK] Seq=1691647408 Ack=3550827905 Len=0
	192.168.1.27	54.171.86.180	TCP 55248 → 2000 [ACK] Seq=3550827905 Ack=1691647409 Len=0
	192.168.1.27	54.171.86.180	TCP 55248 → 2000 [PSH, ACK] Seq=3550827905 Ack=1691647409 Len=2
	54.171.86.180	192.168.1.27	TCP	2000 → 55248 [ACK] Seq=1691647409 Ack=3550827907 Len=0
	54.171.86.180	192.168.1.27	TCP 2000 → 55248 [RST, ACK] Seq=1691647409 Ack=3550827907 Len=0
	 */
	// most likely we sniffed an ACK sent by local host in response to our barrage of RSTs, in
	// which case cr.seq=seq from ACK and cr.ack=ack from ACK
	// nb: don't inject data when sending to remote as otherwise may sniff
	// our own data injection pkts again here in catcher callback and create a
	// positive feedback loop leading to a pkt avalanche
	printf("sending RST\n");
	snd_rst_toremote(&cr, &ld, 0); // will use cr.seq as RST seq number
	snd_rst_toself(&cr, &ld, intf, eth); // will use cr.ack as RST seq number
}

void sigusr1_handler(int signum) {
	// use signal to force exit of sniffer_loop
	catcher_sniffing = 0;
	//pthread_exit(NULL); // occasionally get fault if call this from signal handler
}

void stop_catcher() {
	pthread_kill(catcher_thread,SIGUSR1);
	pthread_join(catcher_thread,NULL);
	for (int i=0; i<sn_esc.num_pds; i++) {
		if (sn_esc.sn[i].pd) pcap_close(sn_esc.sn[i].pd);
		sn_esc.sn[i].pd = NULL;
	}
}

void *catcher(void *ptr) {
	char* filter = ptr;
	// fire up sniffers on each interface
	if (get_interfaces(NULL, 0) == 0) {
		// shouldn't happen since we've already checked for this, so just being careful
		WARN("No valid interfaces for catcher to sniff\n");
	} else {
		sniffer_loop(catcher_callback, &catcher_sniffing, "catcher", filter, &sn_esc, 0);
	}
	return NULL;
}

void *catcher_listener(void *ptr) {
	// wait in accept() loop to handle connections from GUI to catch escapees
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);

	init_libnet(&ld);
	init_libnet(&ld_prompt);
	memset(&a,0,sizeof(catcher_callback_args_t));
	char filter[STR_SIZE];
	int prev_pid = -1;
	
	// setup signal handler for stopping catcher thread
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	//action.sa_flags = SA_RESTART;
	action.sa_handler = sigusr1_handler;
	if (sigaction(SIGUSR1, &action, NULL)<0) {
		WARN("Problem setting SIGUSR1 handler in catcher: %s",strerror(errno));
		return NULL;
	}
	
	for(;;) {
		INFO("Waiting to accept connection on localhost port %u (catch_escapee) ...\n", CATCHER_PORT);
		if ((c_sock2 = accept(c_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			ERR("Problem accepting new connection on localhost port %u (catch_escapee): %s\n", CATCHER_PORT, strerror(errno));
			continue;
		}
		//INFO("Started new connection on port %d\n", CATCHER_PORT);
		// signature check is slow (about 100ms) so we only do it when PID of
		// connecting client changes
		int current_pid = get_sock_pid(c_sock2, CATCHER_PORT);
		if (current_pid != prev_pid) {
			INFO("Prev PID=%d not equal to new PID=%d (catch_escapee), authenticating ...\n",prev_pid,current_pid);
			if (check_signature(c_sock2, CATCHER_PORT)<0) goto err;
		}
		prev_pid = current_pid;

		// read connection parameters
		struct timeval start; gettimeofday(&start, NULL);
		int8_t ok=0;

		ssize_t res; uint8_t vpn;
		memset(&a.target_dst,0,sizeof(struct in6_addr));
		uint32_t ack;
		set_recv_timeout(c_sock2, RECV_TIMEOUT); // to be safe, will eventually timeout of read
		if ( (res=readn(c_sock2, &vpn, sizeof(uint8_t)) )<=0) goto err;
		if ( (res=readn(c_sock2, &a.target_pid, sizeof(int)) )<=0) goto err;
		if ( (res=readn(c_sock2, &a.af, sizeof(int)) )<=0) goto err;
		if ( (res=readn(c_sock2, &a.target_dst, sizeof(struct in6_addr)) )<=0) goto err;
		if ( (res=readn(c_sock2, &a.target_sport, sizeof(uint16_t)) )<=0) goto err;
		if ( (res=readn(c_sock2, &a.target_dport, sizeof(uint16_t)) )<=0) goto err;
		if ( (res=readn(c_sock2, &ack, sizeof(uint32_t)) )<=0) goto err;
		
		char dn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
		inet_ntop(a.af, &a.target_dst, dn, INET6_ADDRSTRLEN);
		INFO("Started new connection on port %d (catch_escapee): pid=%d, af=%d, %u->%s:%u, ack=%u\n",CATCHER_PORT,a.target_pid, a.af,a.target_sport,dn,a.target_dport,ack);
		
		// do some basic sanity checking
		if (a.af!=AF_INET && a.af!=AF_INET6) {
			WARN("Invalid AF value\n");
			ok=-1;
			send(c_sock2, &ok, 1, 0);// just sending 1 byte, shouldn't ever block
			close(c_sock2);
			continue;
		}
				
		conn_raw_t c; memset(&c,0,sizeof(c));
		res = find_fds(a.target_pid, a.af, a.target_dst, a.target_sport, a.target_dport, &c);
		if (res<0) {
			INFO("Couldn't find PID with those connection details (catch_escapee): %d %s:%u\n",a.target_pid,dn,a.target_dport);
			ok=-1;
			send(c_sock2, &ok, 1, 0);// just sending 1 byte, shouldn't ever block
			close(c_sock2);
			continue;
		}

		char* found = find_intf(&c, intf, STR_SIZE, eth);
		if (!found) {
			inet_ntop(c.af, &c.src_addr, sn, INET6_ADDRSTRLEN);
			WARN("catch_escapee(): couldn't find interface for %s->%s\n",sn,dn);
			int ok = 0;
			send(c_sock2, &ok, 1, 0);
			close(c_sock2);
		}
		//sprintf(filter,"tcp and host %s and (port %u or port %u) and (tcp[tcpflags]&tcp-rst==0)", dn, c.sport, c.dport);
		//sprintf(filter,"tcp and host %s and (port %u or port %u) and ( (ip6[6] == 6 and (ip6[53]&tcp-rst==0)) or (tcp[tcpflags]&tcp-rst==0) )", dn, c.sport, c.dport);
		sprintf(filter,"tcp and host %s and (port %u or port %u)", dn, c.sport, c.dport);
		//start pcap listener thread
		a.pkt_count=0;
		catcher_sniffing = 1;
		pthread_create(&catcher_thread, NULL, catcher, filter);
		// if connection is actively sending pkts then catcher thread will sniff
		// them and use the info to send RSTs.
		// but if the connection is idle the catcher thread has no packets to work
		// with, so prompt the connection to come back to life by sending some
		// RSTs. ack is the seq number from the remote.  we need to use a value
		// that lies in current window for RST to provoke a response
		c.seq = 0; c.ack = ack;
		// estimate of recv window of localhost
		// changed top be more aggressive as suspect tcp shrinks window
		// for idle connections
		uint32_t win = 65536/4; // 16K, but we actually probe down to 8K windows in loop below
		// sit here and keep an eye on procinfo.  when connection goes away we can stop.
		//#define WAITTIME 1000 // 1ms
		#define TRIES 33 // 32 plus 1 for initial probe with only INIT_RSTs rst's
		#define INIT_RSTs 128
		#define MAXSEQ 0xFFFFFFFF // 2^32-1
		uint32_t tries_per_round = MAXSEQ/win/(TRIES-1);
		int n=INIT_RSTs;  // initial number of RSTs, enough if seq is right
		// we send RSTs as two inter-leaved sequences shifted by win/2,
		// that way if the window size is large enough we catch it on
		// first round i.e. quicker, otherwise on second round
		printf("starting RST loop\n");
		int first = 1, i=0, j, k, sent=0;
		for (k=0; k<2; k++) {
			c.ack = ack + k*win/2;
			for (i=0; i<TRIES; i++) {
				for (j=0; j<n; j++){
					if (first) {
						res = snd_rst_toself(&c, &ld_prompt, intf, eth); // will use c.ack as RST seq number
						sent++;
						c.ack += win/4;
						if (c.af == AF_INET6) usleep(1000); // for testing
					} else {
						// just send RSTs to self, so don't flood internet
						res = snd_rst_toself(&c, &ld_prompt, intf, eth); // will use c.ack as RST seq number
						sent++;
						c.ack += win;
					}
					if (res<0) goto done; // problem
				}
				conn_raw_t c_temp;
				if (find_fds(a.target_pid, a.af, a.target_dst, a.target_sport, a.target_dport, &c_temp)<0) {
					struct timeval end; gettimeofday(&end, NULL);
					INFO("connection %d %u->%s:%u has STOPPED, pkts sniffed=%d, count %d, sent %d, time taken %fs.\n",a.target_pid,a.target_sport,dn,a.target_dport,a.pkt_count,i,sent,(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);
					ok=1;
					goto done; // connection has gone away
				}
				if (vpn) goto done;
				if (c.af == AF_INET6) goto done; // for testing
				first = 0;
				n = tries_per_round; // let's try a bit harder !
			}
		}
	done:
		printf("finished RST loop\n");
		if (ok != 1) {
			struct timeval end; gettimeofday(&end, NULL);
			INFO("FAILED to stop connection %d %d->%s:%u, pkts sniffed=%d, count=%d, sent=%d, time taken %fs\n",a.target_pid,a.target_sport,dn,a.target_dport,a.pkt_count,i,sent,(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);
		}
		// tell GUI we're done ...
		//fcntl(c_sock2, F_SETFL, O_NONBLOCK); // make non-blocking
		send(c_sock2, &ok, 1, 0);
		// stop pcap listeners.
		stop_catcher();
		// and tidy up
		close(c_sock2);
		continue;
	err:
		INFO("Connection on port %u for %d %s ended (catch_escapee): %s\n", prev_pid, CATCHER_PORT, dn, strerror(errno));
		// stop pcap listeners.
		stop_catcher();
		close(c_sock2);
	}
	return NULL;
}

void start_catcher_listener() {
	c_sock = bind_to_port(CATCHER_PORT,2);
	INFO("Now listening on localhost port %u (catch_escapee)\n", CATCHER_PORT);
	pthread_create(&catcher_listener_thread, NULL, catcher_listener, NULL);
}
