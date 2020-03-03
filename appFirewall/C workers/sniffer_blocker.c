//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "sniffer_blocker.h"

// libpcap tutorial: https://www.tcpdump.org/pcap.html

// globals
static pthread_t thread; // handle to listener thread
static pthread_mutex_t wait_list_mutex = MUTEX_INITIALIZER;
static int r_sock, p_sock;
static int is_running=0;
static int num_conns_blocked=0;
static list_t waiting_list=LIST_INITIALISER;

// cache recent UDP connections so only log new ones
// (since no internal ESTABLISHED state held, unlike TCP)
typedef struct udp_conn_t {
	int af;
	struct in6_addr dst;
	int sport, dport;
} udp_conn_t;

#define MAXUDP 50
udp_conn_t udp_cache[MAXUDP]={{0,{0},0,0}};
struct timeval udp_cache_tstamp[MAXUDP]={{0,0}};
int udp_cache_size=0, udp_cache_start=0;


//--------------------------------------------------------
// private functions

bl_item_t create_blockitem_from_addr(conn_raw_t *cr, int syn, int pkt_pid, char* pkt_name) {
	// create a new blocklist item from raw connection info (assumed to be
	// outgoing connection, so src is local and dst is remote)
	// populates all of blocklist item, including PID name and domain name
	bl_item_t c;
	memset(&c,0,sizeof(c));

	// get human readable form of dest adddr
	inet_ntop(cr->af, &cr->dst_addr, c.addr_name, INET6_ADDRSTRLEN);
	char src[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->src_addr, src, INET6_ADDRSTRLEN);

	int pid;
	
	if ((pkt_pid>0) && pkt_name && (strnlen(pkt_name,MAXCOMLEN)>0)) {
		// great, we got the pid and nanme from the pcap header.
		pid = pkt_pid;
		strlcpy(c.name,pkt_name,MAXCOMLEN);
		cache_pid(pid, c.name);
		stats.pktap_hits++;
		printf("%s:%u->%s:%u found from PKTAP: %s\n", src,cr->sport,c.addr_name,cr->dport,c.name);
	} else {
		stats.pktap_misses++;
		// start by trying netstat info ...
		printf("%s:%u->%s:%u NOT found from PKTAP.\n",src,cr->sport,c.addr_name,cr->dport);
		// next try to get PID from dtrace cache ...
		int res=lookup_dtrace(cr, c.name, &pid);
		if (res==0) { // rare when dtrace is active, otherwise boring
			INFO2("%s:%u->%s:%u NOT found in dtrace cache, trying procinfo ... ", src,cr->sport,c.addr_name,cr->dport);
			if (syn)
				stats.dtrace_syn_misses++;
			else
				stats.dtrace_misses++;
			// finally try to get PID info from /proc ...
			// nb: >90% of execution time of create_blockitem_from_addr()
			// is spent in this find_pid() call, and within that call
			// find_fds consumes >85% of execution time
			res=find_pid(cr,c.name,syn);
			//clock_t end1 = clock();
			if (res==0) {
				// we'll now add this conn to waiting list and try again once
				// /proc has updated or new dtrace info arrives
				strcpy(c.name,NOTFOUND);
			}
		} else {
			if (syn)
				stats.dtrace_syn_hits++;
			else
				stats.dtrace_hits++;
			cache_pid(pid, c.name); // cache successful pid for pidinfo lookup
			INFO2("%s:%u->%s:%u found in dtrace cache: %s\n", src,cr->sport,c.addr_name,cr->dport,c.name);
		}
	}
	
	// try to get domain name from DNS cache
	char* dns =lookup_dns_name(cr->af, cr->dst_addr);
	if (dns!=NULL) {
		//printf("dns found for %s\n",dns);
		strlcpy(c.domain,dns,MAXDOMAINLEN);
		free(dns);
		// append this process name to list of processes
		// that have connected to this domain.  we can then use this
		// to guess the process name for later <not found> connections
		if (strcmp(c.name,NOTFOUND)!=0) add_dns_conn(c.domain, c.name);
		stats.num_noguess++;
	} else {
		//printf("dns not found for %s\n",c.addr_name);
		strlcpy(c.domain,c.addr_name,MAXDOMAINLEN);
		// try to do a reverse lookup, this might take a while so its run in
		// a separate thread and we don't wait here for the result
		reverse_dns_lookup(cr->af, cr->dst_addr);
	}
	
	return c;
}

void process_conn(conn_raw_t *cr, bl_item_t *c, double confidence, int *r_sock, int logstats) {

		int blocked = is_blocked(c);
		DEBUG2("%s %s %d\n",c->name,c->addr_name,blocked);
		// if we're really not sure about process name then don't
		// block.  can tune aggressiveness by adjusting threshold here
		char* conf_str="";
		if ((confidence < CONF_THRESH) && (strcmp(c->name,NOTFOUND)!=0)) {
			blocked = 0;
			conf_str="?";
		}

		// log the connection
		char dn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
		inet_ntop(cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
		inet_ntop(cr->af, &cr->src_addr, sn, INET6_ADDRSTRLEN);
		log_connection(cr, c, blocked, confidence, conf_str,"", get_name_path(c->name));

		if (!blocked) {
			INFO2("t (sniffed) %f ", (cr->start.tv_sec - cr->ts.tv_sec) +(cr->start.tv_usec - cr->ts.tv_usec)/1000000.0);
			struct timeval end; gettimeofday(&end, NULL);
			INFO2("(not blocked) %f\n", (end.tv_sec - cr->ts.tv_sec) +(end.tv_usec - cr->ts.tv_usec)/1000000.0);
			if (logstats) {
				double t=(cr->start.tv_sec - cr->ts.tv_sec) +(cr->start.tv_usec - cr->ts.tv_usec)/1000000.0;
				cm_add_sample_lock(&stats.cm_t_sniff,t);
				t=(end.tv_sec - cr->ts.tv_sec) +(end.tv_usec - cr->ts.tv_usec)/1000000.0;
				cm_add_sample_lock(&stats.cm_t_notblocked,t);
			}
			return; // nothing more needs done
		}
		
		num_conns_blocked++;
		//return;
		
		// send RST packet to try to end connection
		// ask helper process (which has root permissions) to send
		// RST packet via raw socket
		DEBUG2("sending af=%d, sport=%u, dport=%u, ack=%d, seq=%u, %s -> %s\n",cr->af,cr->sport, cr->dport,cr->seq,cr->ack,dn,c->addr_name);
		int syn = 0;
		set_snd_timeout(*r_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
		if (send(*r_sock, &syn, sizeof(int),0)<0) goto err_r;
		if (send(*r_sock, &cr->af, sizeof(int),0)<0) goto err_r;
		if (send(*r_sock, &cr->src_addr, sizeof(struct in6_addr),0)<0) goto err_r;
		if (send(*r_sock, &cr->sport, sizeof(uint16_t),0)<0) goto err_r;
		if (send(*r_sock, &cr->dst_addr, sizeof(struct in6_addr),0)<0) goto err_r;
		if (send(*r_sock, &cr->dport, sizeof(uint16_t),0)<0) goto err_r;
		if (send(*r_sock, &cr->seq, sizeof(uint32_t),0)<0) goto err_r;
		if (send(*r_sock, &cr->ack, sizeof(uint32_t),0)<0) goto err_r;
	
		//clock_t end = clock();
		//printf("t (blocked) %f\n",(end - begin)*1.0 / CLOCKS_PER_SEC);
		INFO2("t (sniffed) %f ", (cr->start.tv_sec - cr->ts.tv_sec) +(cr->start.tv_usec - cr->ts.tv_usec)/1000000.0);
		struct timeval end; gettimeofday(&end, NULL);
		INFO2(" (blocked) %f\n", (end.tv_sec - cr->ts.tv_sec) +(end.tv_usec - cr->ts.tv_usec)/1000000.0);
		if (logstats) {
			double t = (cr->start.tv_sec - cr->ts.tv_sec) +(cr->start.tv_usec - cr->ts.tv_usec)/1000000.0;
			cm_add_sample_lock(&stats.cm_t_sniff,t);
			t = (end.tv_sec - cr->ts.tv_sec) +(end.tv_usec - cr->ts.tv_usec)/1000000.0;
			cm_add_sample_lock(&stats.cm_t_blocked,t);
		}
		return;
		
	err_r:
		WARN("send pkt: %s\n", strerror(errno));
		close(*r_sock); // if don't close and reopen sock we get error
		if ( (*r_sock=connect_to_helper(RST_PORT,0)) <0 ) {
			//fatal error
			is_running=0;
			pthread_exit(NULL);
		}
		return;
}

size_t get_waiting_list_size() {
	return get_list_size(&waiting_list);
}

void clear_waiting_list() {
	clear_list(&waiting_list);
}

void init_waiting_list() {
	init_list(&waiting_list,conn_raw_hash,NULL,1,-1,"waiting_list");
}

void add_waiting_list(conn_raw_t *cr) {
	add_item(&waiting_list,cr,sizeof(conn_raw_t));
}

void process_conn_waiting_list(void) {
		// try to process waiting conns. called whenever pid info is updated,
		// so have a hope of being able to remove conns from list
		
		TAKE_LOCK(&wait_list_mutex,"process_conn_waiting_list()");

		if (get_waiting_list_size() !=0 ) {
			INFO2("waiting list size = %zu, hits=%d, misses=%d\n",get_list_size(&waiting_list),stats.waitinglist_hits,stats.waitinglist_misses);
		}
		struct timeval end; gettimeofday(&end, NULL);
		size_t i = 0;
		while (i<get_waiting_list_size() ) {
			conn_raw_t cr_w;
			memcpy(&cr_w,get_list_item(&waiting_list,i),sizeof(conn_raw_t));
			pthread_mutex_unlock(&wait_list_mutex);
			int del=0;
			
			// try to get PID name for this connection ...
			bl_item_t c_w = create_blockitem_from_addr(&cr_w, 0, -1, NULL);

			if (strcmp(c_w.name,NOTFOUND)==0) {//yet again failed to get PID name
				if ( (end.tv_sec - cr_w.ts.tv_sec) +(end.tv_usec - cr_w.ts.tv_usec)/1000000.0
						> WAIT_TIMEOUT) {
					INFO2("wait timeout for %s %s\n",c_w.name,c_w.addr_name);
					
					// look up domain name and use most frequent process
					double confidence = 1.0;
					char* name = guess_name(c_w.domain,&confidence);
					if (name != NULL) {
						strlcpy(c_w.name, name, MAXCOMLEN);
						stats.num_guesses++;
					} else {
						// failed to lookup or guess the process name for conn,
						// let's log this interesting event
						INFO("NOT FOUND on dns_conn_list: %s\n", c_w.domain);
						//dump_dns_conn_list();
						stats.num_failed_guesses++;
					}
					
					// process
					process_conn(&cr_w, &c_w, confidence, &r_sock,0);
					
					// record stats
					stats.waitinglist_misses++;
					struct timeval end; gettimeofday(&end, NULL);
					double t=(end.tv_sec - cr_w.ts.tv_sec) +(end.tv_usec - cr_w.ts.tv_usec)/1000000.0;
					cm_add_sample_lock(&stats.cm_t_waitinglist_miss,t);
					// flag that need to remove this conn from waiting list
					del=1;
				} else {
					// an outstanding conn, refresh pid info again
					signal_pid_watcher(0,0);
				}
			} else {
				// got process name, we can proceed
				INFO2("delayed processing of %s %s\n",c_w.name,c_w.addr_name);
				process_conn(&cr_w, &c_w, 1.0, &r_sock,0); // process
				stats.waitinglist_hits++;
				struct timeval end; gettimeofday(&end, NULL);
				double t=(end.tv_sec - cr_w.ts.tv_sec) +(end.tv_usec - cr_w.ts.tv_usec)/1000000.0;
				cm_add_sample_lock(&stats.cm_t_waitinglist_hit,t);
				del = 1; // flag that need to remove this conn from waiting list
			}
			
			TAKE_LOCK(&wait_list_mutex,"process_conn_waiting_list() #2");
			if (del==1) {
				del_item(&waiting_list,&cr_w); // remove from waiting list
				// no need to update i as removing conn from list
				// will have shifted a new conn into row i of list
			} else {
				i++;
			}
		}
		pthread_mutex_unlock(&wait_list_mutex);
}

u_char* payload(u_char* pkt) {
	// step past IP header
	int version = (*pkt)>>4; // get IP version
	u_char* nexth=NULL; // this will point to TCP/UDP header
	if (version == 4) {
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)pkt;
		nexth=((u_char *)ip + (ip->ip_hl * 4));
	} else {
		struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)pkt;
		nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
	}
	return nexth;
}

conn_raw_t get_conn_from_pkt(u_char* pkt, int* syn, int* synack) {
	// extract connection details from received packet
	conn_raw_t cr; memset(&cr,0,sizeof(cr));
	
	int version = (*pkt)>>4; // get IP version
	int proto, af;
	struct in6_addr src, dst;
	memset(&src,0,sizeof(src)); memset(&dst,0,sizeof(dst));
	u_char* nexth=NULL; // this will point to TCP/UDP header
	if (version == 4) {
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)pkt;
		proto=ip->ip_p;
		af=AF_INET;
		memcpy(&src,&ip->ip_src,sizeof(struct in_addr));
		memcpy(&dst,&ip->ip_dst,sizeof(struct in_addr));
		nexth=((u_char *)ip + (ip->ip_hl * 4));
	} else {
		struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)pkt;
		proto=ip->ip_nh;
		af=AF_INET6;
		memcpy(&src,&ip->ip_src,sizeof(struct in6_addr));
		memcpy(&dst,&ip->ip_dst,sizeof(struct in6_addr));
		nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
	}
	if (proto == IPPROTO_UDP) {
		struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)nexth;
		uint16_t sport=ntohs(udp->uh_sport);
		uint16_t dport=ntohs(udp->uh_dport);
		cr.af=af; cr.udp=1;
		// only incoming UDP pkts are logged, flip things around since we always store
		// conn details with reference to outgoing pkts
		cr.src_addr=dst; cr.dst_addr=src; cr.sport=dport; cr.dport=sport;
		*syn = 0; *synack = 0;
	} else if (proto == IPPROTO_TCP) {
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
		*syn = (tcp->th_flags & (TH_SYN)) && !(tcp->th_flags & (TH_ACK));
		*synack = (tcp->th_flags & (TH_SYN)) && (tcp->th_flags & (TH_ACK));
		cr.af=af; cr.udp=0;
		if (*syn) {
			// when SYN the src is local and dst is remote
			cr.src_addr=src; cr.dst_addr=dst;
			cr.sport=ntohs(tcp->th_sport); cr.dport=ntohs(tcp->th_dport);
			cr.seq=ntohl(tcp->th_seq); cr.ack=ntohl(tcp->th_ack);
		} else { // SYN-ACK
			// blocklist assumes outgoing connections,
			// when SYN-ACK the src is remote and dst is local so need to flip them
			cr.src_addr=dst; cr.dst_addr=src;
			cr.sport=ntohs(tcp->th_dport); cr.dport=ntohs(tcp->th_sport);
			cr.seq=ntohl(tcp->th_ack); cr.ack=ntohl(tcp->th_seq);
			// our info is from a syn-ack and local host will have sent an ack in
			// response and so we need to account for this.
			cr.ack++;
		}
	} else {// neither UDP nor TCP
		cr.udp = -1;
	}
	return cr;
}

int in_udp_cache(conn_raw_t *cr) {
	int i;
	for (i=udp_cache_start; i<udp_cache_start+udp_cache_size; i++) {
		if (udp_cache[i%MAXUDP].af != cr->af) continue;
		if (udp_cache[i%MAXUDP].sport != cr->sport) continue;
		if (udp_cache[i%MAXUDP].dport != cr->dport) continue;
		if (are_addr_same(cr->af,&udp_cache[i%MAXUDP].dst,&cr->dst_addr)) {
			//printf("match\n");
			struct timeval now; gettimeofday(&now, NULL);
			if (udp_cache_tstamp[i%MAXUDP].tv_sec - now.tv_sec < UDP_CACHE_LIFETIME)
				return 1; // found match
			else { // stale match
				udp_cache[i%MAXUDP].af = -1; // effectively deletes this cache entry
				return 0;
			}
		}
	}
	return 0; // no match
}

void clear_udp_cache() {
	udp_cache_size = 0;
	udp_cache_start = 0;
}

void add_to_udp_cache(conn_raw_t *cr) {
	if (udp_cache_size==MAXUDP) {
		udp_cache_start++; udp_cache_size--;
	}
	int end = (udp_cache_start+udp_cache_size)%MAXUDP;
	udp_cache[end].af=cr->af; udp_cache[end].sport=cr->sport;
	udp_cache[end].dport=cr->dport; udp_cache[end].dst=cr->dst_addr;
	gettimeofday(&udp_cache_tstamp[end], NULL); // timestamp when conn started
	udp_cache_size++;
}

void write_conn_details_to_console(conn_raw_t *cr, int pkt_pid, char* pkt_name) {
	// write connection details to console
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->src_addr, sn, INET6_ADDRSTRLEN);
	inet_ntop(cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
	char *udp_str=""; if (cr->udp==1) udp_str="UDP";
	printf("%s (%d) %s %s:%d -> %s:%d\n",pkt_name,pkt_pid,udp_str,sn,cr->sport,dn,cr->dport);
}

void handle_udp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name) {
	// don't log localhost connections
	if ((cr->af==AF_INET) && (is_ipv4_localhost(&cr->src_addr))) return;
	if ((cr->af==AF_INET6) && (is_ipv6_localhost(&cr->src_addr))) return;
	// don't log mDNS local broadcast traffic
	if ((cr->sport == 5353)||(cr->dport==5353)) return;
	
	// don't log existing UDP connections
	if (in_udp_cache(cr)) return;
	
	// new connection
	add_to_udp_cache(cr); // add connection to cache
	
	write_conn_details_to_console(cr, pkt_pid, pkt_name);

	// carry out PID and DNS lookup
	bl_item_t c = create_blockitem_from_addr(cr,0,pkt_pid,pkt_name);
	// if can't link connection to a PID then for UDP we just guess (for TCP
	// we add connection to waiting list and try again - maybe we should
	// do same for UDP?)
	int quic = ((cr->sport == 443) || (cr->dport == 443) || (cr->sport == 80) || (cr->dport == 80));
	if ((strcmp(c.name,NOTFOUND)==0) && quic) {
		// we seem to often miss process for quic pkts, for now
		// we guess its Chrome.
		strlcpy(c.name,"Google Chrome H",MAXCOMLEN);
		stats.num_guesses++;
	}
	
	// log connection
	char dns[MAXDOMAINLEN]={0};
	if (strnlen(c.domain,MAXDOMAINLEN)) {
		snprintf(dns,MAXDOMAINLEN, "%s (%s)", c.addr_name,c.domain);
	}
	char* service="UDP ";
	if (quic) {
		service = "UDP/QUIC ";
	} else if ((cr->sport==53) || (cr->dport==53)) {
		service = "UDP/DNS ";
	}
	// blocked = 0 for UDP, at the moment
	log_connection(cr, &c, 0, 1.0, "",service, get_name_path(c.name));
	
	// and log some performance stats
	double t =(cr->start.tv_sec - cr->ts.tv_sec) +(cr->start.tv_usec - cr->ts.tv_usec)/1000000.0;
	INFO2("t (sniffed) %f ", t);
	cm_add_sample_lock(&stats.cm_t_sniff,t);
	struct timeval endu; gettimeofday(&endu, NULL);
	t =(endu.tv_sec - cr->ts.tv_sec) +(endu.tv_usec - cr->ts.tv_usec)/1000000.0;
	INFO2(" (UDP not blocked) %f\n",t );
	cm_add_sample_lock(&stats.cm_t_udp,t);
}

void handle_tcp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name, int syn, int synack) {
	if ( (!syn) && (!synack)) {
		// not SYN or SYN-ACK, ignore.  shouldn't happen
		WARN("sniffed tcp pkt is not syn/syn-ack\n");
		return;
	}
	// don't log localhost connections
	if ((cr->af==AF_INET) && (is_ipv4_localhost(&cr->src_addr))) return;
	if ((cr->af==AF_INET6) && (is_ipv6_localhost(&cr->src_addr))) return;

	write_conn_details_to_console(cr, pkt_pid, pkt_name);

	// try to get PID name and domain for this connection ...
	bl_item_t c = create_blockitem_from_addr(cr, syn, pkt_pid, pkt_name);
	
	if (syn) {
		// when not using dtrace or pktap we use
		// syn's to prime the procinfo cache.  if connection is not in
		// cache we trigger a refresh here.  the hope is that by the time the
		// synack arrives the connection will be in the cache and we'll avoid
		// waiting.
		if (strcmp(c.name,NOTFOUND)==0) signal_pid_watcher(0,0);
		return; // nothing more to do for a syn.
	}
	
	if (strcmp(c.name,NOTFOUND)==0) {
		// failed to look up PID name
		// put into waiting list to try again
		TAKE_LOCK(&wait_list_mutex,"listener()");
		add_waiting_list(cr);
		pthread_mutex_unlock(&wait_list_mutex);
	} else {
		// got PID name, proceed with processing ...
		// if on block list, send rst.  otherwise just log conn and move on
		process_conn(cr, &c, 1.0, &r_sock, 1);
	}
	// refresh pid info (may take a while, so we don't wait here).  serves a
	// dual purpose:
	// 1. if have just added conn to waiting list because can't find the conn in
	// the current pidinfo list of processes and conns then this will cause the
	// list to be updated, so that hopefully can now find the conn and take it
	// off waiting list
	// 2. for a conn which we've just processed refresh of pidinfo will cause a
	// check that conn has really died, and if not will call helper to catch the
	// "escapee".
	signal_pid_watcher(0,0);
}

void *listener(void *ptr) {
	struct pcap_pkthdr pkthdr;
	u_char pkt[SNAPLEN];
	ssize_t res;
	
	is_running=1; // flag that thread is running
	
	if ( (p_sock=connect_to_helper(PCAP_PORT,0))<0 ) {
		//fatal error
		is_running=0;
		INFO("Exiting listener\n");
		pthread_exit(NULL);
	}
	if ( (r_sock=connect_to_helper(RST_PORT,0)) <0 ) {
		//fatal error
		is_running=0;
		INFO("Exiting listener\n");
		pthread_exit(NULL);
	}

	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	init_waiting_list();
	//init_dns_conn_list();
	
	// set up handler for waiting list (connections for which we didn't manage to
	// get the process name immediately)
	set_pid_watcher_hook(process_conn_waiting_list);  // when pid info updated
	set_dtrace_watcher_hook(process_conn_waiting_list); // when dtrace is updated
	
	for(;;) { // we sit in loop waiting for sniffed pkt into from helper
		
		// read sniffed pkt, this will block
		DEBUG2("waiting to read sniffed pkt ... %d\n",p_sock);
		if ( (res=readn(p_sock, &pkthdr, sizeof(struct pcap_pkthdr)) )<=0) goto err_p;
		if (pkthdr.caplen>SNAPLEN) {
			WARN("Sniffer listener: our snaplen %d is too small for received pkt len %d\n",SNAPLEN,pkthdr.caplen);
			pkthdr.caplen=SNAPLEN; // we truncate packet and hope for the best !
		}
		size_t pkt_proper_len=0;
		int pkt_pid=-1;
		char pkt_name[MAXCOMLEN]; memset(pkt_name,0,MAXCOMLEN);
		ssize_t len=0;
		if ( (res=readn(p_sock, &pkt_pid, sizeof(int)) )<=0) goto err_p;
		if ( (res=readn(p_sock, &len, sizeof(ssize_t)) )<=0) goto err_p;
		if (len>0) {
			if ( (res=readn(p_sock, pkt_name, len) )<=0) goto err_p;
		} else {
			printf("pid=%d, len=%zd ...",pkt_pid,len);
		}
		if ( (res=readn(p_sock, &pkt_proper_len, sizeof(size_t)) )<=0) goto err_p;
		if ( (res=readn(p_sock, pkt, (ssize_t)pkt_proper_len) )<=0) goto err_p;
		
		// we got a pkt, let's process it ...		
		// nb: link layer header has already been removed by helper.
		struct timeval ts = pkthdr.ts;
		struct timeval start; gettimeofday(&start, NULL);
		// stale packets are dropped, likely due to wakeup after sleep.
		if (start.tv_sec - ts.tv_sec > SYN_TIMEOUT) {
			INFO("received stale pkt, %f old. discard\n",(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0);
			continue;
		}

		// extract connection details from pkt
		int syn=0, synack=0;
		conn_raw_t cr = get_conn_from_pkt(pkt, &syn, &synack);
		cr.ts = ts; cr.start = start;
		if (cr.udp == -1) {// neither TCP nor UDP
			// shouldn't happen
			WARN("sniffed pkt is neither udp nor tcp\n");
			continue;
		}
		
		// extract lookup info from UDP DNS packets (we ignore TCP DNS, they're rare)
		int dns = (cr.sport == 53 || cr.dport == 53
							|| cr.sport == 5353 || cr.dport == 5353);
		if ((cr.udp==1) && dns) {
			// pass to DNS sniffer for parsing
			double t = (start.tv_sec - cr.ts.tv_sec) +(start.tv_usec - cr.ts.tv_usec)/1000000.0;
			//INFO2("t (sniffed dns) %f\n", t);
			int dirn = dns_sniffer(payload(pkt),pkt_proper_len);
			cm_add_sample_lock(&stats.cm_t_dns,t);
			if (dirn != 1) continue; // don't log outgoing DNS requests
		}
		
		if (cr.udp==1) { // UDP
			handle_udp_conn(&cr, pkt_pid, pkt_name);
		} else { // TCP
			handle_tcp_conn(&cr, pkt_pid, pkt_name, syn, synack);
		}
	continue;
		
	err_p:
		if (errno==0) {
			WARN("recv sniffed pkt: connection closed.\n");
		} else if (errno == EOPNOTSUPP) {
			// get this error when code sign check on helper fails, we won't recover from this so tell
			// the user
			set_error_msg("Problem in sniffer-blocker receiving packet data from helper, likely a code signing issue.  Try reinstalling helper.",1);
			is_running=0; pthread_exit(NULL);
		} else {
			WARN("recv sniffed pkt: %s (%d)\n", strerror(errno), errno);
		}
		// likely helper has shut down sniffing connection for some reason, reopen it
		close(p_sock); // if don't close and reopen sock we get error
		if ( (p_sock=connect_to_helper(PCAP_PORT,0))<0 ) {is_running=0; pthread_exit(NULL);} //fatal error
		continue;
	}
}

//--------------------------------------------------------
// swift interface

void start_listener() {
	// fire up thread that listens for pkts sent by helper
	pthread_create(&thread, NULL, listener, NULL);
}

void stop_listener() {
	pthread_kill(thread, SIGTERM);
	close(p_sock); // end connection to helper, this will let helper close pktap dev
}

int sniffer_blocker_error() {
	return !is_running;
}

int check_for_error() {
	// nb: we can only generate error popup from
	// within the main GUI thread, not from within listener() thread.
	// so we get GUI thread to poll listener status using this routing

	// we don't fail on the dtrace or escapee connections failing as
	// we can survive that, but its fatal if sniffer_blocker conns fail
	return sniffer_blocker_error();
}

int_sw get_num_conns_blocked() {
	return num_conns_blocked;
}

void set_num_conns_blocked(int val) {
	num_conns_blocked=val;
}

//--------------------------------------------------------

/*
void get_tcp_options(const u_char* pkt, struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp, int pcap_off) {
	// extract TCP options.  don't use this just now, but might be handy in future

	// we'll cast tcp header to this data structure ...
	struct sniff_tcp {
			u_short th_sport;
			u_short th_dport;
			u_int th_seq;
			u_int th_ack;
			u_char th_offx2;
		#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
			u_char th_flags;
		#define TH_FIN 0x01
		#define TH_SYN 0x02
		#define TH_RST 0x04
		#define TH_PUSH 0x08
		#define TH_ACK 0x10
		#define TH_URG 0x20
		#define TH_ECE 0x40
		#define TH_CWR 0x80
		#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
			u_short th_win;
			u_short th_sum;
			u_short th_urp;
	};

	// parse the options
	struct sniff_tcp *tcp2 = (struct sniff_tcp *)
		((u_char *)ip + (ip->ip_hl * 4));
	uint8_t offset = ((tcp2->th_offx2 & 0xf0) >> 4) * 4;
	typedef struct {
		uint8_t kind;
		uint8_t size;
	} tcp_option_t;
	uint8_t* opt = (uint8_t*)(pkt + pcap_off + LIBNET_IPV4_H + LIBNET_TCP_H);
	uint8_t count=0;
	//printf("%d %d\n",offset,tcp->th_x2);
	while( (*opt != 0) && count<offset-LIBNET_TCP_H) {
		tcp_option_t* _opt = (tcp_option_t*)opt;
		if( _opt->kind == 1  ) {
			 //printf("nop, ");
			 count++; opt++;
			 continue;
		}
		if( _opt->kind == 2  ) {
			//printf("mss %d, ",ntohs(*(uint16_t*)(opt+2)));
		} if( _opt->kind == 4 ) {
			//printf("SackOk, ");
		} else if( _opt->kind == 8  ) {
			//printf("TS val %u ecr %u, ",
			ntohl(*(uint32_t*)(opt+2)),ntohl(*(uint32_t*)(opt+6))
			);
		} else if( _opt->kind == 3  ) {
			//printf("wscale: %d, ",*(opt+2));
		}
		count +=_opt->size; opt += _opt->size;
	}
	//printf("\n");
}
*/
