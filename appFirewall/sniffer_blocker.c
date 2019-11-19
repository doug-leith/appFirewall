#include "sniffer_blocker.h"

// libpcap tutorial: https://www.tcpdump.org/pcap.html

// globals
static pthread_t thread; // handle to listener thread
static int r_sock, p_sock;
static int is_running=0;
static int num_conns_blocked=0;

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

void *listener(void *ptr) {
	struct pcap_pkthdr pkthdr;
	#define SNAPLEN 512 // needs to be big enough to capture dns payload
	u_char pkt[SNAPLEN];
	int res;
	
	is_running=1; // flag that thread is running
	
	if ( (p_sock=connect_to_helper(PCAP_PORT))<0 ) {is_running=0; pthread_exit(NULL);} //fatal error
	if ( (r_sock=connect_to_helper(RST_PORT)) <0 ) {is_running=0; pthread_exit(NULL);} //fatal error

	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	for(;;) { // we sit in loop waiting for sniffed pkt into from helper
		
		// read sniffed pkt, this will block
		DEBUG2("waiting to read sniffed pkt ... %d\n",p_sock);
		if ( (res=readn(p_sock, &pkthdr, sizeof(struct pcap_pkthdr)) )<=0) goto err_p;
		if (pkthdr.caplen>SNAPLEN) {
			WARN("Sniffer listener: our snaplen %d is too small for received pkt len %d ",SNAPLEN,pkthdr.caplen);
			pkthdr.caplen=SNAPLEN; // we truncate packet and hope for the best !
		}
		DEBUG2("waiting to read pkt ...\n");
		if ( (res=readn(p_sock, pkt, pkthdr.caplen) )<=0) goto err_p;
		
		// we got a pkt, let's process it ...
		const int pcap_off = 14; // ethernet link layer offset
		
		clock_t begin = clock();
		
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
			int sport=ntohs(udp->uh_sport);
			int dport=ntohs(udp->uh_dport);
			if (sport == 53 || dport == 53) {
				// pass to DNS sniffer
				dns_sniffer(&pkthdr,nexth);
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
					bl_item_t c = create_blockitem_from_addr(&cr);
					// log connection
					char dns[BUFSIZE]={0};
					if (strlen(c.domain)) {
						sprintf(dns,"%s (%s)",c.addr_name,c.domain);
					}
					char str[LOGSTRSIZE], long_str[LOGSTRSIZE], sn[INET6_ADDRSTRLEN];
					inet_ntop(af, &src, sn, INET6_ADDRSTRLEN);
					sprintf(str,"%s → UDP/QUIC %s:%d", c.name, c.domain, dport);
					sprintf(long_str,"%s UDP/QUIC %s:%d -> %s:%d", c.name, sn, sport, dns, dport);
					append_log(str, long_str, &c, &cr, 0); // can't block QUIC yet ...
					
					clock_t endu = clock();
					printf("t (UDP not blocked) %f\n",(endu - begin)*1.0 / CLOCKS_PER_SEC);
				}
			}
			continue;
		}
		
		if (proto != IPPROTO_TCP) continue; // shouldn't happen
		
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
		
		if ( !(tcp->th_flags & (TH_SYN)) || !(tcp->th_flags & (TH_ACK)) ) {
			// its not a SYN-ACK (i.e. must be a SYN), ignore
			continue;
		}

		// SYN-ACK, so src is remote and dst is local
		// on blocklist ?
		conn_raw_t cr;
		cr.af=af; cr.src_addr=dst; cr.dst_addr=src; cr.udp=0; cr.sport=ntohs(tcp->th_dport); cr.dport=ntohs(tcp->th_sport);
		
		bl_item_t c = create_blockitem_from_addr(&cr);

		int blocked=0;
		if (in_whitelist_htab(&c,0)!=NULL) {
			// whitelisted
			blocked=0;
		} else {
			if (in_blocklist_htab(&c,0)!=NULL) { // table lookup, faster !
				blocked=1;
				//in_blocklist_htab(&c,1); // dumps hash table, for debugging
			} else if (in_blocklists_htab(&c) != NULL) {
				// in block list file
				blocked = 3;
			} else if (in_hostlist_htab(c.domain) != NULL) {
				// in hosts list
				blocked = 2;
			}
		}
		DEBUG2("%s %s %d\n",c.name,c.addr_name,blocked);

		// log the connection
		char str[LOGSTRSIZE], long_str[LOGSTRSIZE], dn[INET6_ADDRSTRLEN];
		inet_ntop(af, &dst, dn, INET6_ADDRSTRLEN);
		char dns[BUFSIZE], dst_name[BUFSIZE];
		if (strlen(c.domain)>0) {
			sprintf(dns,"%s (%s)",c.addr_name,c.domain);
			strlcpy(dst_name,c.domain,BUFSIZE);
		} else {
			strlcpy(dns,c.addr_name,BUFSIZE);
			strlcpy(dst_name,c.addr_name,BUFSIZE);
		}
		sprintf(str,"%s → %s:%d", c.name, dst_name, cr.dport);
		sprintf(long_str,"%s %s:%d -> %s:%d", c.name, dn, cr.dport, dns, cr.sport);
		append_log(str, long_str, &c, &cr, blocked);

		if (!blocked) {
			clock_t end = clock();
			printf("t (not blocked) %f\n",(end - begin)*1.0 / CLOCKS_PER_SEC);
			continue; // nothing more needs done
		}
		
		num_conns_blocked++;
		
		// send RST packet to try to end connection
		uint32_t seq=ntohl(tcp->th_seq);
		uint32_t ack=ntohl(tcp->th_ack);
		uint16_t dport=ntohs(tcp->th_dport);
		uint16_t sport=ntohs(tcp->th_sport);
		// ask helper process (which has root permissions) to send
		// RST packet via raw socket
		DEBUG2("sending af=%d, sport=%d, dport=%d, ack=%d, seq=%d, %s -> %s\n",af,dport, sport,seq,ack,dn,c.addr_name);
		if (send(r_sock, &af, sizeof(int),0)<0) goto err_r;
		if (send(r_sock, &dst, sizeof(struct in6_addr),0)<0) goto err_r;
		if (send(r_sock, &dport, sizeof(uint16_t),0)<0) goto err_r;
		if (send(r_sock, &src, sizeof(struct in6_addr),0)<0) goto err_r;
		if (send(r_sock, &sport, sizeof(uint16_t),0)<0) goto err_r;
		if (send(r_sock, &ack, sizeof(uint32_t),0)<0) goto err_r;
		if (send(r_sock, &seq, sizeof(uint32_t),0)<0) goto err_r;
		
		clock_t end = clock();
		printf("t (blocked) %f\n",(end - begin)*1.0 / CLOCKS_PER_SEC);
		continue;

	err_p:
		if (errno==0) {
			WARN("recv sniffed pkt: connection closed.");
		} else {
			WARN("recv sniffed pkt: %s", strerror(errno));
		}
		// likely helper has shut down sniffing connection for some reason, reopen it
		close(p_sock); // if don't close and reopen sock we get error
		if ( (p_sock=connect_to_helper(PCAP_PORT))<0 ) {is_running=0; pthread_exit(NULL);} //fatal error
		continue;
		
	err_r:
		WARN("send pkt: %s", strerror(errno));
		close(p_sock); // if don't close and reopen sock we get error
		if ( (r_sock=connect_to_helper(RST_PORT)) <0 ) {is_running=0; pthread_exit(NULL);} //fatal error
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

int listener_error() {
	// nb: we can only raise signal that generates error popup from
	// within the main GUI thread, not from within listener() thread.
	// so we get GUI thread to poll listener status using this routing
	return !is_running;
	// should really take a lock on is_running var, but its just an int so
	// almost certainly updated by thread atomically
}

int get_num_conns_blocked() {
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
