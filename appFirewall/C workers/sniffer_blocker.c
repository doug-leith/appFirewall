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
udp_conn_t udp_cache[MAXUDP];
int udp_cache_size=0, udp_cache_start=0;


//--------------------------------------------------------
// private functions




bl_item_t create_blockitem_from_addr(conn_raw_t *cr, int syn) {
	// create a new blocklist item from raw connection info (assumed to be
	// outgoing connection, so src is local and dst is remote)
	// populates all of blocklist item, including PID name and domain name
	bl_item_t c;
	memset(&c,0,sizeof(c));

	// get human readable form of dest adddr
	inet_ntop(cr->af, &cr->dst_addr, c.addr_name, INET6_ADDRSTRLEN);
	char src[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->src_addr, src, INET6_ADDRSTRLEN);

	// can we get PID from dtrace cache ?
	int pid;
	int res=lookup_dtrace(cr, c.name, &pid);
	if (res==0) { // rare when dtrace is active, otherwise boring
		INFO2("%s:%u->%s:%u NOT found in dtrace cache, trying procinfo ... ", src,cr->sport,c.addr_name,cr->dport);
		if (syn)
			stats.dtrace_syn_misses++;
		else
			stats.dtrace_misses++;
		// try to get PID info from /proc
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
		char str[LOGSTRSIZE], long_str[LOGSTRSIZE], dn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
		inet_ntop(cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
		inet_ntop(cr->af, &cr->src_addr, sn, INET6_ADDRSTRLEN);
		char dns[MAXDOMAINLEN], dst_name[MAXDOMAINLEN];
		if (strlen(c->domain)>0) {
			sprintf(dns,"%s (%s)",c->addr_name,c->domain);
			strlcpy(dst_name,c->domain,MAXDOMAINLEN);
		} else {
			strlcpy(dns,c->addr_name,MAXDOMAINLEN);
			strlcpy(dst_name,c->addr_name,MAXDOMAINLEN);
		}
		sprintf(str,"%s%s → %s:%u", c->name, conf_str, dst_name, cr->dport);
		sprintf(long_str,"%s\t%s:%u -> %s:%u\t(blocked=%d, confidence=%.2f)", c->name, sn, cr->sport, dns, cr->dport,blocked, confidence);
		append_log(str, long_str, c, cr, blocked, confidence);

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

void process_conn_waiting_list(void) {
		// try to process waiting conns. called whenever pid info is updated,
		// so have a hope of being able to remove conns from list
		
		TAKE_LOCK(&wait_list_mutex,"process_conn_waiting_list()");

		if (get_list_size(&waiting_list) !=0 ) {
			INFO2("waiting list size = %zu, hits=%d, misses=%d\n",get_list_size(&waiting_list),stats.waitinglist_hits,stats.waitinglist_misses);
		}
		struct timeval end; gettimeofday(&end, NULL);
		size_t i = 0;
		while (i<get_list_size(&waiting_list) ) {
			conn_raw_t cr_w;
			memcpy(&cr_w,get_list_item(&waiting_list,i),sizeof(conn_raw_t));
			pthread_mutex_unlock(&wait_list_mutex);
			int del=0;
			
			// try to get PID name for this connection ...
			bl_item_t c_w = create_blockitem_from_addr(&cr_w, 0);

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
					signal_pid_watcher(0);
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

void *listener(void *ptr) {
	struct pcap_pkthdr pkthdr;
	#define SNAPLEN 512 // needs to be big enough to capture dns payload
	u_char pkt[SNAPLEN];
	ssize_t res;
	
	is_running=1; // flag that thread is running
	
	if ( (p_sock=connect_to_helper(PCAP_PORT,0))<0 ) {
		//fatal error
		is_running=0;
		printf("Exiting listener\n");
		pthread_exit(NULL);
	}
	if ( (r_sock=connect_to_helper(RST_PORT,0)) <0 ) {
		//fatal error
		is_running=0;
		printf("Exiting listener\n");
		pthread_exit(NULL);
	}

	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	init_list(&waiting_list,conn_raw_hash,NULL,1,-1,"waiting_list");
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
			WARN("Sniffer listener: our snaplen %d is too small for received pkt len %d ",SNAPLEN,pkthdr.caplen);
			pkthdr.caplen=SNAPLEN; // we truncate packet and hope for the best !
		}
		DEBUG2("waiting to read pkt ...\n");
		if ( (res=readn(p_sock, pkt, (ssize_t)pkthdr.caplen) )<=0) goto err_p;
		
		// we got a pkt, let's process it ...
		const int pcap_off = 14; // ethernet link layer offset
		
		struct timeval ts = pkthdr.ts;
		struct timeval start; gettimeofday(&start, NULL);
		// stale SYN packets are dropped, likely due to wakeup after sleep.  
		if (start.tv_sec - ts.tv_sec > SYN_TIMEOUT) {
			INFO("received stale syn-ack, %f old. discard\n",(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0);
			continue;
		}

		int version = (*(pkt + pcap_off))>>4; // get IP version
		int proto, af;
		struct in6_addr src, dst;
		memset(&src,0,sizeof(src)); memset(&dst,0,sizeof(dst));
		u_char* nexth=NULL; // this will point to TCP/UDP header
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
		DEBUG2("version %d proto %d (udp=%d, tcp=%d)\n",version,proto,IPPROTO_UDP,IPPROTO_TCP);
		
		if (proto == IPPROTO_UDP) {
			struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)nexth;
			uint16_t sport=ntohs(udp->uh_sport);
			uint16_t dport=ntohs(udp->uh_dport);
			if (sport == 53 || dport == 53) {
				// pass to DNS sniffer
				double t =(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0;
				INFO2("t (sniffed dns) %f\n", t);
				dns_sniffer(&pkthdr,nexth);
				cm_add_sample_lock(&stats.cm_t_dns,t);
				continue;
			} else if (dport == 443) {
				// likely to be quic.  can't block it yet, but can log the
				// connection
				//printf("UDP %d/%d %d\n",sport, dport,udp_cache_size);
				conn_raw_t cr;
				cr.af=af; cr.src_addr=src; cr.dst_addr=dst; cr.sport=sport; cr.dport=dport; cr.udp=1;
				int i;
				for (i=udp_cache_start; i<udp_cache_start+udp_cache_size; i++) {
					if (udp_cache[i%MAXUDP].af != af) continue;
					if (udp_cache[i%MAXUDP].sport != sport) continue;
					if (udp_cache[i%MAXUDP].dport != dport) continue;
					if (are_addr_same(af,&udp_cache[i%MAXUDP].dst,&dst)) {
						//printf("match\n");
						break; // found match
					}
				}
				if (i == udp_cache_start+udp_cache_size) {
					// new connection, log it
					
					// add to connection cache
					if (udp_cache_size==MAXUDP) {
						udp_cache_start++; udp_cache_size--;
					}
					int end = (udp_cache_start+udp_cache_size)%MAXUDP;
					udp_cache[end].af=af; udp_cache[end].sport=sport;
					udp_cache[end].dport=dport; udp_cache[end].dst=dst;
					udp_cache_size++;
					
					// carry out PID and DNS lookup
					bl_item_t c = create_blockitem_from_addr(&cr,0);
					if (strcmp(c.name,NOTFOUND)==0) {
						// we seem to often miss process for a UDP pkt, for now
						// we guess its Chrome.
						strlcpy(c.name,"Google Chrome H",MAXCOMLEN);
						stats.num_guesses++;
					}
					// log connection
					char dns[MAXDOMAINLEN]={0};
					if (strlen(c.domain)) {
						sprintf(dns,"%s (%s)",c.addr_name,c.domain);
					}
					char str[LOGSTRSIZE], long_str[LOGSTRSIZE], sn[INET6_ADDRSTRLEN];
					inet_ntop(af, &src, sn, INET6_ADDRSTRLEN);
					sprintf(str,"%s → UDP/QUIC %s:%u", c.name, c.domain, dport);
					sprintf(long_str,"%s\tUDP/QUIC %s:%u -> %s:%u", c.name, sn, sport, dns, dport);
					append_log(str, long_str, &c, &cr, 0, 1.0); // can't block QUIC yet ...
					
					double t =(start.tv_sec - ts.tv_sec) +(start.tv_usec - ts.tv_usec)/1000000.0;
					INFO2("t (sniffed) %f ", t);
					cm_add_sample_lock(&stats.cm_t_sniff,t);
					struct timeval endu; gettimeofday(&endu, NULL);
					t =(endu.tv_sec - ts.tv_sec) +(endu.tv_usec - ts.tv_usec)/1000000.0;
					INFO2(" (UDP not blocked) %f\n",t );
					cm_add_sample_lock(&stats.cm_t_udp,t);
				}
			}
			continue;
		}
		
		if (proto != IPPROTO_TCP) {
			// shouldn't happen
			WARN("sniffed pkt is not tcp\n");
			continue;
		}

		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
		int syn = (tcp->th_flags & (TH_SYN)) && !(tcp->th_flags & (TH_ACK));
		int synack = (tcp->th_flags & (TH_SYN)) && (tcp->th_flags & (TH_ACK));
		if ( (!syn) && (!synack)) {
			// not SYN or SYN-ACK, ignore.  shouldn't happen
			WARN("sniffed tcp pkt is not syn/syn-ack\n");
			continue;
		}
			
		conn_raw_t cr;
		cr.af=af; cr.udp=0;
		cr.ts = ts; cr.start = start;
		if (syn) {
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
		}
		// try to get PID name and domain for this connection ...
		bl_item_t c = create_blockitem_from_addr(&cr, syn);
		
		if (syn) {
			// we use syn's to prime the procinfo cache.  if connection is not in
			// cache we trigger a refresh here.  the hope is that by the time the
			// synack arrives the connection will be in the cache and we'll avoid
			// waiting.
			if (strcmp(c.name,NOTFOUND)==0) signal_pid_watcher(0);
			continue; // nothing more to do for a syn.
		}
		
		if (strcmp(c.name,NOTFOUND)==0) {
			// failed to look up PID name
			// put into waiting list to try again
			TAKE_LOCK(&wait_list_mutex,"listener()");
			add_item(&waiting_list,&cr,sizeof(conn_raw_t));
			pthread_mutex_unlock(&wait_list_mutex);
		} else {
			// got PID name, proceed with processing ...
			// if on block list, send rst.  otherwise just log conn and move on
			process_conn(&cr, &c, 1.0, &r_sock, 1);
		}
		// refresh pid info (may take a while, so we don't wait here).  serves a dual purpose:
		// 1. if have just added conn to waiting list because can't find the conn in
		// the current pidinfo list of processes and conns then this will cause the list
		// to be updated, so that hopefully can now find the conn and take it off waiitng list
		// 2. for a conn which we've just processed refresh of pidinfo will cause a
		// check that conn has really died, and if not will call helper to catch the
		// "escapee".		
		signal_pid_watcher(0);
		continue;
		
	err_p:
		if (errno==0) {
			WARN("recv sniffed pkt: connection closed.");
		} else {
			WARN("recv sniffed pkt: %s", strerror(errno));
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
			 printf("nop, ");
			 count++; opt++;
			 continue;
		}
		if( _opt->kind == 2  ) {
			printf("mss %d, ",ntohs(*(uint16_t*)(opt+2)));
		} if( _opt->kind == 4 ) {
			printf("SackOk, ");
		} else if( _opt->kind == 8  ) {
			printf("TS val %u ecr %u, ",
			ntohl(*(uint32_t*)(opt+2)),ntohl(*(uint32_t*)(opt+6))
			);
		} else if( _opt->kind == 3  ) {
			printf("wscale: %d, ",*(opt+2));
		}
		count +=_opt->size; opt += _opt->size;
	}
	printf("\n");
}
*/
