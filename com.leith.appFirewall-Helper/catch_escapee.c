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

//source for tcp protocol block:
//https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netinet/tcp_var.h.auto.html


#include "catch_escapee.h"

//globals
static pcap_t *pd_esc;  // pcap listener
static pthread_t catcher_thread; // handle to catcher thread
static pthread_t catcher_listener_thread; // handle to catcher_listener thread
static int c_sock, c_sock2=-1;
static pthread_cond_t catcher_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t catcher_mutex = PTHREAD_MUTEX_INITIALIZER;
static int wakeup = 0;

static libnet_data_t ld, ld_prompt;

typedef struct catcher_callback_args_t {
	uint16_t target_dport;
	int pkt_count;
} catcher_callback_args_t;

int find_fds(int pid, int af, struct in6_addr dst, uint16_t port, conn_raw_t *cr) {
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
		if (c.dport != port) continue;
		if (!are_addr_same(c.af, &c.dst_addr, &dst)) continue;
		*cr = c;
		free(procFDInfo);
		return 0;
	}

	free(procFDInfo);
	return -1;
}

void catcher_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// we got a pkt, let's process it ...
	catcher_callback_args_t *a=(catcher_callback_args_t*)args;
	uint16_t target_dport = a->target_dport;
	a->pkt_count++; // record number of packets we've snifeed for this connection

	const int pcap_off = 14; // ethernet link layer offset
	
	struct timeval ts = pkthdr->ts;
	struct timeval start; gettimeofday(&start, NULL);
	double t=(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0;
	#define TIMEOUT 2 //packets >2s old are dropped, likely due to wakeup after sleep
	if (t > TIMEOUT) {
		INFO2("catcher_callback received stale pkt, %f old. discard\n",t);
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
	
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
	
	uint16_t sport=ntohs(tcp->th_sport);
	uint16_t dport=ntohs(tcp->th_dport);
	uint32_t seq=ntohl(tcp->th_seq);
	uint32_t ack=ntohl(tcp->th_ack);

	conn_raw_t cr;
	cr.af=af;
	if (dport == target_dport) {
		// outgoing packet
		cr.src_addr=src; cr.dst_addr=dst;
		cr.sport=sport; cr.dport=dport;
		cr.seq=seq;
		// ack in RST is really an ack for previous pkt from localhost, not this one.
		// snd_rst() will add +1 to this value
		cr.ack=ack-1;
	} else if (sport == target_dport)  {
		// incoming packet
		cr.src_addr=dst; cr.dst_addr=src;
		cr.sport=dport; cr.dport=sport;
		cr.seq=ack; cr.ack=seq;
	} else {
		WARN("received packet with mismatched ports, sport=%u/dport=%u but expected dport=%u (catch_escapee)\n",sport,dport,target_dport);
		return;
	}
	
	snd_rst(0,&cr,0,&ld);
}

void *catcher(void *ptr) {
	for (;;) {
		pthread_mutex_lock(&catcher_mutex);
		// release mutex and wait for signal to wake up
		while (wakeup==0) {
			if (pthread_cond_wait(&catcher_cond, &catcher_mutex)!=0) {
				WARN("catcher_watcher() cond error: %s", strerror(errno));
			}
		}
		wakeup=0;
		pthread_mutex_unlock(&catcher_mutex);
		
		if (pcap_loop(pd_esc, -1,	catcher_callback, (u_char*)ptr)==PCAP_ERROR){	// this blocks
			ERR("catche_escapee pcap_loop: %s\n", pcap_geterr(pd_esc));
		}
		// catcher_listener calls pcap_breakloop() when connection is
		// stopped or timeout occurs
	}
}

void *catcher_listener(void *ptr) {
	// wait in accept() loop to handle connections from GUI to catch escapees
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);

	init_libnet(&ld);
	init_libnet(&ld_prompt);
	
	// setup pcap sniffer data structure with this filter
	bpf_u_int32 mask = start_sniffer(&pd_esc, NULL);

	catcher_callback_args_t a;
	memset(&a,0,sizeof(catcher_callback_args_t));
	wakeup=0;
	pthread_create(&catcher_thread, NULL, catcher, &a);
	int prev_pid = -1;
	for(;;) {
		INFO("Waiting to accept connection on localhost port %u (catch_escapee) ...\n", CATCHER_PORT);
		if ((c_sock2 = accept(c_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			ERR("Problem accepting new connection on localhost port %u (catch_escapee): %s\n", CATCHER_PORT, strerror(errno));
			continue;
		}
		//INFO("Started new connection on port %d\n", CATCHER_PORT);
		// signature check is slow (about 100ms) so we only do it when PID of connecting client
		// changes
		int current_pid = get_sock_pid(c_sock2, CATCHER_PORT);
		if (current_pid != prev_pid) {
			INFO("Prev PID=%d ot equal to new PID=%d (catch_escapee), authenticating ...\n",prev_pid,current_pid);
			if (check_signature(c_sock2, CATCHER_PORT)<0) goto err;
		}
		prev_pid = current_pid;

		// read connection parameters
		struct timeval start; gettimeofday(&start, NULL);
		int8_t ok=0;

		ssize_t res; int af, pid;
		struct in6_addr dst;
		memset(&dst,0,sizeof(struct in6_addr));
		uint16_t target_dport=0;
		uint32_t ack;
		set_recv_timeout(c_sock2, RECV_TIMEOUT); // to be safe, will eventually timeout of read
		if ( (res=readn(c_sock2, &pid, sizeof(int)) )<=0) goto err;
		if ( (res=readn(c_sock2, &af, sizeof(int)) )<=0) goto err;
		if ( (res=readn(c_sock2, &dst, sizeof(struct in6_addr)) )<=0) goto err;
		if ( (res=readn(c_sock2, &target_dport, sizeof(uint16_t)) )<=0) goto err;
		if ( (res=readn(c_sock2, &ack, sizeof(uint32_t)) )<=0) goto err;
		
		char dn[INET6_ADDRSTRLEN];
		inet_ntop(af, &dst, dn, INET6_ADDRSTRLEN);
		INFO("Started new connection on port %d (catch_escapee): pid=%d, af=%d, %s:%u, ack=%u\n",CATCHER_PORT,pid, af,dn,target_dport,ack);
		
		// do some basic sanity checking
		if (af!=AF_INET && af!=AF_INET6) continue;
				
		conn_raw_t c; memset(&c,0,sizeof(c));
		res = find_fds(pid, af, dst, target_dport, &c);
		if (res<0) {
			INFO("Couldn't find PID with those connection details (catch_escapee): %d %s:%u\n",pid,dn,target_dport);
			ok=-1;
			send(c_sock2, &ok, 1, 0);// just sending 1 byte, shouldn't ever block
			close(c_sock2);
			continue;
		}

		char filter[1024];
		sprintf(filter,"tcp and host %s and (port %u or port %u) and (tcp[tcpflags]&tcp-rst==0)", dn, c.sport, c.dport);
		struct bpf_program fp;		/* The compiled filter expression */
		if (pcap_compile(pd_esc, &fp, filter, 0, mask) == -1) {
			ERR("Couldn't parse pcap filter %s (catch_escapee): %s\n", filter, pcap_geterr(pd_esc));
			//exit(EXIT_FAILURE);
			continue;
		}
		if (pcap_setfilter(pd_esc, &fp) == -1) {
			ERR("Couldn't install pcap filter %s (catch_escapee): %s\n", filter, pcap_geterr(pd_esc));
			//exit(EXIT_FAILURE);
			continue;
		}
		//restart pcap listener thread
		a.target_dport = target_dport; a.pkt_count=0;
		pthread_mutex_lock(&catcher_mutex);
		wakeup = 1;
		pthread_cond_signal(&catcher_cond);
		pthread_mutex_unlock(&catcher_mutex);

		// if connection is actively sending pkts then catcher thread will sniff them
		// and use the info to send RSTs.
		// but if the connection is side the catcher thread has no packets to work with,
		// so we try to prompt the connection to come back to life by sending some RSTs.
		// ack is the seq number from the remote.  we need to use a value that lies
		// in current window for RST to provoke a response
		c.seq = 0; c.ack = ack;
		uint32_t win = 65536/2; // estimate of recv window of localhost		
		// sit here and keep an eye on procinfo.  when connection goes away we can stop.
		#define WAITTIME 5000 // 1ms
		#define TRIES 33 // 32 plus 1 for initial probe with only INIT_RSTs rst's
		#define INIT_RSTs 5
		// 2^32/win = 131072, so need to send this many probe RSTs to cover seq space
		// 131072/32 = 4096
		#define LATER_RSTs 4096
		int i, n=INIT_RSTs;
		for (i=0; i<TRIES; i++) {
			for (int j=0; j<n; j++){
				snd_rst(0,&c,1,&ld_prompt); // just send RSTs to self, so don't flood internet
				c.ack += win; // ack might be stale, so advance it by a few windows
			}
			conn_raw_t c_temp;
			int res = find_fds(pid, af, dst, target_dport, &c_temp);
			if (res<0) {
				struct timeval end; gettimeofday(&end, NULL);
				INFO("connection %d %s:%u has STOPPED, pkts sniffed=%d, count %d, time taken %fs.\n",pid,dn,target_dport,a.pkt_count,i,(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);
				ok=1;
				break; // connection has gone away
			}
			usleep(WAITTIME);
			n = LATER_RSTs; // let's try a bit harder !
		}
		if (i==TRIES) {
			struct timeval end; gettimeofday(&end, NULL);
			INFO("FAILED to stop connection %d %s:%u, pkts sniffed=%d, time taken %fs\n",pid,dn,target_dport,a.pkt_count,(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);
		}
		// tell GUI we're done ...
		//fcntl(c_sock2, F_SETFL, O_NONBLOCK); // make non-blocking
		send(c_sock2, &ok, 1, 0);
		// stop pcal listener
		pcap_breakloop(pd_esc);
		// and tidy up
		close(c_sock2);
		continue;
	err:
		INFO("Connection on port %u for %d %s ended (catch_escapee): %s\n", prev_pid, CATCHER_PORT, dn, strerror(errno));
		pcap_breakloop(pd_esc);
		close(c_sock2);
	}
	return NULL;
}

void start_catcher_listener() {
	c_sock = bind_to_port(CATCHER_PORT,25);
	INFO("Now listening on localhost port %u (catch_escapee)\n", CATCHER_PORT);
	pthread_create(&catcher_listener_thread, NULL, catcher_listener, NULL);
}
