//
//  send_rst.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "send_rst.h"

// nice info on raw sockets: https://sock-raw.org/papers/sock_raw
// RFC on RST attack mitigations: https://tools.ietf.org/html/rfc5961#section-3.2
// nice blog post on TCP RST details: https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/

// example of a syn-synack-rst exchange between macos and linux:
/*192.168.1.27	54.171.86.180	TCP	78			2730891158	2730891158	55054 → 2000 [SYN] Seq=2730891158 Win=65535 Len=0 MSS=1460 WS=64 TSval=708234657 TSecr=0 SACK_PERM=1
54.171.86.180	192.168.1.27	TCP	82			614073368	614073368	2000 → 55054 [SYN, ACK] Seq=614073368 Ack=2730891159 Win=26847 Len=0 MSS=1420 SACK_PERM=1 TSval=4013502325 TSecr=708234657 WS=128
192.168.1.27	54.171.86.180	TCP	66			2730891159	2730891159	55054 → 2000 [ACK] Seq=2730891159 Ack=614073369 Win=132352 Len=0 TSval=708234674 TSecr=4013502325
54.171.86.180	192.168.1.27	TCP	74			614073369	614073369	2000 → 55054 [RST, ACK] Seq=614073369 Ack=2730891159 Win=26880 Len=0 TSval=4013505869 TSecr=708234674
*/

// example of a syn-rst exchange:
/*IP snowdrop.55035 > leith.ie.telnet: Flags [S], seq 3192423600, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 707813899 ecr 0,sackOK,eol], length 0
IP leith.ie.telnet > snowdrop.55035: Flags [R.], seq 0, ack 3192423601, win 0, length 0
*/

// example of reset after data sent
/*192.168.1.27	54.171.86.180	TCP	78			3550827904	3550827904	55248 → 2000 [SYN] Seq=3550827904 Win=65535 Len=0 MSS=1460 WS=64 TSval=712321874 TSecr=0 SACK_PERM=1
54.171.86.180	192.168.1.27	TCP	82			1691647408	1691647408	2000 → 55248 [SYN, ACK] Seq=1691647408 Ack=3550827905 Win=26847 Len=0 MSS=1420 SACK_PERM=1 TSval=4019473278 TSecr=712321874 WS=128
192.168.1.27	54.171.86.180	TCP	66			3550827905	3550827905	55248 → 2000 [ACK] Seq=3550827905 Ack=1691647409 Win=132352 Len=0 TSval=712321890 TSecr=4019473278
192.168.1.27	54.171.86.180	TCP	68			3550827905	3550827907	55248 → 2000 [PSH, ACK] Seq=3550827905 Ack=1691647409 Win=132352 Len=2 TSval=712328780 TSecr=4019473278
54.171.86.180	192.168.1.27	TCP	74			1691647409	1691647409	2000 → 55248 [ACK] Seq=1691647409 Ack=3550827907 Win=26880 Len=0 TSval=4019480187 TSecr=712328780
54.171.86.180	192.168.1.27	TCP	66			1691647409	1691647409	2000 → 55248 [RST, ACK] Seq=1691647409 Ack=3550827907 Win=26880 Len=0 TSval=4019484652 TSecr=712328780
*/

//globals
static int sock, s2;
static libnet_data_t ld_rst;
static int select_timeouts=0, select_num=0, select_count=0; // for monitoring IPv6 rate limiting
static time_t select_time={0};

void close_rst_sock() {
	close(sock); close(s2);
}

void start_rst() {
	// start listening for commands to send RST packets
	sock = bind_to_port(RST_PORT,2);
	INFO("Now listening on localhost port %d (send_rst)\n", RST_PORT);
}

void init_libnet(libnet_data_t *ld) {
	// now initialise libnet packet processing data structure
	char err_buf[LIBNET_ERRBUF_SIZE];
	
	INFO("init_libnet\n");
	memset(ld,0,sizeof(libnet_data_t));
	
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
	// kernel constructs source address of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	ld->l4_hdr=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4_hdr==NULL) {
		ERR("libnet_init() IPv4 l4_hdr failed, won't be able to kill network connections: %s\n", err_buf);
	}
	int n = 1;
	if (setsockopt(ld->l4_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		WARN("libnet setsockopt l4_hdr IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}
	
	// no IP_HDRINCL option for IPV6 though, sigh
	ld->l6_hdr = NULL; memset(&ld->last_intf,0,sizeof(interface_t)); ld->pd=NULL;
}

void free_libnet(libnet_data_t *ld) {
	INFO("free_libnet()\n");
	if (ld->l4) libnet_destroy(ld->l4);
	if (ld->l6) libnet_destroy(ld->l6);
	if (ld->l4_hdr) libnet_destroy(ld->l4_hdr);
	if (ld->l6_hdr) libnet_destroy(ld->l6_hdr);
	if (ld->pd) pcap_close(ld->pd);
	memset(ld,0,sizeof(libnet_data_t));
}

libnet_ptag_t append_ether6(libnet_t *l, libnet_ptag_t *eth_ptag, uint8_t eth_dst[ETHER_ADDR_LEN]) {
	// construct link-layer ethernet header, only used for IPv6 packets
	// src and dst MACs are the same since we're sending to self
	//int i; for(i=0; i<ETHER_ADDR_LEN;i++) printf("%02x ",eth_dst[i]); printf("\n");
	*eth_ptag = libnet_build_ethernet(
		eth_dst,      				 /* ethernet destination */
		eth_dst,     					 /* ethernet source */
		ETHERTYPE_IPV6,        /* protocol type */
		NULL,                  /* payload */
		0,                     /* payload size */
		l,                     /* libnet handle */
		*eth_ptag);            /* libnet id */
	return *eth_ptag;
}

libnet_ptag_t append_ipheader(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr, libnet_t *l, libnet_ptag_t *ip_ptag, uint16_t len) {
	// construct IP header
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
		*ip_ptag = libnet_build_ipv6(0,0,LIBNET_TCP_H+len,
																 IPPROTO_TCP, 64,
																 s, d,
																 NULL, 0, l, *ip_ptag);
	}
	return *ip_ptag;
}

int snd_rst_toself(conn_raw_t* c, libnet_data_t *ld, interface_t* intf) {
	// send RST to self.  parameter c contains connection details, assumed to be for an outgoing conn
	// nb: normally the kernel writes the sender info in packet header itself when we use raw socket.
	// to avoid this with IPv4 we use the IP_HDRINCL socket option.  this option doesn't exist for
	// IPv6 though, so for IPv6 we need to send via the link layer (what a pointless hassle !)
	// nb2: fails with VPNs (at least with openVPN as it messes up packets sent to self).

	interface_t temp_intf;
	
	libnet_ptag_t *tcp_hdr_ptag, *ip_hdr_ptag;
	libnet_t *l_hdr=NULL;
	if (c->af==AF_INET) {// ipv4
		l_hdr = ld->l4_hdr; tcp_hdr_ptag=&ld->tcp4_hdr_ptag; ip_hdr_ptag=&ld->ip4_hdr_ptag;
	} else { // ipv6
		// IPV6 doesn't support IP_HDRINCL flag, so we have to
		// send to self via link layer.  that means we have to
		// recreate libnet data struct whenever the interface used changes
			if ((ld->l6_hdr==NULL) || (ld->pd==NULL) // initial call
							|| (intf==NULL) // caller would like us to work out the interface for them
							|| (strcmp(ld->last_intf.name,intf->name)!=0) ){ // change in interface being used
			// we're opening a /dev/bpf device for link layer pkt injection, its easy to run out of these
			// so we have to be careful to tidy up and avoid any "leaks"
			if (ld->l6_hdr) {libnet_destroy(ld->l6_hdr); ld->l6_hdr = NULL;}
			if (ld->pd) {pcap_close(ld->pd); ld->pd=NULL;}
			 

			if (intf==NULL) {
				// caller wants us to figure out which interface to use ourselves
				if (!find_intf(c, &temp_intf)) {
					char sn[INET6_ADDRSTRLEN],dn[INET6_ADDRSTRLEN];
					inet_ntop(c->af, &c->src_addr, sn, INET6_ADDRSTRLEN);
					inet_ntop(c->af, &c->dst_addr, dn, INET6_ADDRSTRLEN);
					WARN("snd_rst_toself(): couldn't find interface for %s->%s\n",sn,dn);
					goto err;
				}
			} else {
				memcpy(&temp_intf,intf,sizeof(interface_t));
			}
			char err_buf[LIBNET_ERRBUF_SIZE];
			ld->l6_hdr=libnet_init(LIBNET_LINK,temp_intf.name,err_buf);
			if (ld->l6_hdr==NULL) {
				ERR("libnet_init() IPv6 in snd_rst_toself() failed for interface %s, won't be able to kill network connections to self: %s\n", temp_intf.name, err_buf);
				goto err;
			}
			ld->tcp6_hdr_ptag = LIBNET_PTAG_INITIALIZER; ld->ip6_hdr_ptag = LIBNET_PTAG_INITIALIZER;
			ld->eth_ptag = LIBNET_PTAG_INITIALIZER;

			if (temp_intf.is_eth) {
				char filter_exp[STR_SIZE], *eth_str;
				eth_str = ether_ntoa((struct ether_addr*)&temp_intf.eth);
				sprintf(filter_exp,"ip6 and ether dst %s and ether src %s",eth_str,eth_str);
				DEBUG2("pcap filter: %s\n",filter_exp);
				int res=setup_pd(&temp_intf, &ld->pd, filter_exp, 0);
				if ((res < 0)||(ld->pd==NULL)) {
					WARN("Problem in snd_rst_toself()creating sniffer for interface %s\n",temp_intf.name); goto err;
				}
				pcap_setnonblock(ld->pd,1,NULL);
			} else {
				// most likely this will happen with IPv6 tunnels, which are point-to-point interfaces and so
				// have no MAC address.  we're ok with IP4 tunnels though.
				// TO DO: handle IPv6 tunnels
				WARN("Interface %s has no MAC address in snd_rst_toself(), perhaps an IPv6 tunnel?\n",temp_intf.name); goto err;
			}
			
			// remember interface for next time
			memcpy(&ld->last_intf,&temp_intf,sizeof(interface_t));
		} else {
			memcpy(&temp_intf,intf,sizeof(interface_t));
		}
		
		l_hdr = ld->l6_hdr; tcp_hdr_ptag=&ld->tcp6_hdr_ptag; ip_hdr_ptag=&ld->ip6_hdr_ptag;
	}
	
	if (l_hdr == NULL) {// shouldn't happen
		WARN("l_hdr==NULL in snd_rst_toself()\n"); goto err;
	}

	uint8_t flags = TH_RST;
	if (c->seq) flags=TH_RST|TH_ACK;
	if ((*tcp_hdr_ptag = libnet_build_tcp(c->dport,c->sport,c->ack,c->seq,flags, //ack+1
																	 0, 0, 0, LIBNET_TCP_H, NULL, 0, l_hdr, *tcp_hdr_ptag))==-1) {
		WARN("libnet_build_tcp() in snd_rst_toself(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (append_ipheader(c->af, &c->dst_addr, &c->src_addr, l_hdr, ip_hdr_ptag, 0)==-1) {
		WARN("libnet_build_ip() in snd_rst_toself(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (c->af == AF_INET6) {
		// add link layer header for IPv6
		ld->eth_ptag = append_ether6(l_hdr, &ld->eth_ptag, temp_intf.eth);
		if (ld->eth_ptag<0)  {
			WARN("append_ether6() in snd_rst_toself(): %s\n", libnet_geterror(l_hdr)); goto err;
		}
	}
	int res = libnet_write(l_hdr);

	// res is negative if error, else the number of bytes sent
	if (res <= 0) {
		WARN("libnet_write() in snd_rst_toself(): %s\n", libnet_geterror(l_hdr)); goto err;
	} else {
		// one might suppose that res < pkt size might flag overflow in IPv6
		// link layer pkt injection, but we always
		// get res = pkt_size even if injected packet is dropped, so resort
		// to pcap feedback approach below instead
		/* uint8_t *packet = NULL; uint32_t pkt_len;
		libnet_pblock_coalesce(l_hdr, &packet, &pkt_len);
		if (res != pkt_len) {
			WARN("libnet_write() in snd_rst_toself() sent %d of pkt %d\n",res,pkt_len);
		}*/
	}

	if (c->af == AF_INET6) {
		// more IPv6 raw socket fun.  link layer writes are unbuffered and so we
		// need to do some congestion control to limit rate at which we inject
		// packets.  we use pcap to sniff packets sent from self to self (i.e.
		// with src and dst MAC addresses the same) and after calling libnet_write()
		// we wait until something appears -- we expect to sniff
		// packet twice, once outgoing and once incoming.
		if (!ld->pd) { // shouldn't happen, but fall back to crude rate limiting
			sleep(IPV6_SELECT_TIMEOUT);
		} else {
			int fd = pcap_get_selectable_fd(ld->pd);
			fd_set readfds; FD_ZERO(&readfds);FD_SET(fd,&readfds);
			struct timeval timeout;
			timeout.tv_sec = 0; timeout.tv_usec = IPV6_SELECT_TIMEOUT; // 1ms
			ssize_t res=0;
			while ( (res=select(fd+1, &readfds, NULL, NULL, &timeout))==EINTR);
			if (res<0) { // res=0 on timeout, <0 on error
				WARN("snd_rst select: %s (res=%zd)\n", strerror(errno), res);
			} else {
				// a timeout means that no packet was sniffed, so timeouts are
				// an indicator of loss of injected packets and we'd like to
				// keep the number low
				if (res==0) select_timeouts++;
				if (FD_ISSET(fd,&readfds)) {
					struct pcap_pkthdr buf; const u_char* ptr;
					int count=0;
					while ((ptr=pcap_next(ld->pd, &buf))!=NULL) count++;
					// expect to sniff each RST packet twice (once
					// outgoing and once incoming), but might see more here
					// since we'll sniff RSTs sent by every thread.  more
					// problematic might be if we see less, since that suggests
					// drops either when injecting packets or when sniffing them.
					//printf("read %d pkts from pcap\n", count);
					select_num++; select_count+=count;
				}
				// periodically log stats ... we don't want to be seeing too many
				// timeouts since they likely correspond to link layer losses
				time_t select_now = time(NULL);
				if (select_now-select_time > 600) {
					select_time = select_now;
					INFO("IPv6 select stats: timeouts=%d (%.2f percent), success=%d (%.2f percent), sniffed pkt count=%d (avg %.2f)\n", select_timeouts, select_timeouts*100.0/(select_timeouts+select_num), select_num, select_num*100.0/(select_timeouts+select_num), select_count, select_count*1.0/select_num);
					fflush(stdout);
				}

			}
		}
	}

	return 1;
	
err:
	free_libnet(ld); init_libnet(ld);
	return -1;
}

int snd_rst_toremote(conn_raw_t* c, libnet_data_t *ld, int try_data) {
	// send RST to remote destination.  parameter c contains connection details, assumed to be for an
	// outgoing conn
	libnet_ptag_t *tcp_ptag, *ip_ptag;
	libnet_t *l=NULL;
	if (c->af==AF_INET) {// ipv4
		l = ld->l4; tcp_ptag=&ld->tcp4_ptag; ip_ptag=&ld->ip4_ptag;
	} else { // ipv6
		l= ld->l6; tcp_ptag=&ld->tcp6_ptag; ip_ptag=&ld->ip6_ptag;
	}

	if (l == NULL) {// shouldn't happen
		WARN("l==NULL in snd_rst_toremote()\n"); goto err;
	}

	uint16_t len = 0;
	if (try_data) {
		// this is a bit nasty.  we try to inject data into the connection to
		// generate an error at the remote which will cause it to reset the
		// connection. helpful with VPNs where sending RST to self doesn't work, so
		// getting remote to send RST is useful.
		const char *buf = "drop connection {\n\n\n"; // invalid json and http
		len = (uint16_t)strlen(buf);
		if (!try_data) len = 0; // disable data injection attack
		*tcp_ptag = libnet_build_tcp(c->sport, c->dport, c->seq, c->ack, TH_ACK, 4096, 0, 0, LIBNET_TCP_H, (uint8_t*)buf, len, l, *tcp_ptag);
		append_ipheader(c->af, &c->src_addr, &c->dst_addr, l, ip_ptag, len);
		if (libnet_write(l)==-1) {
			WARN("write data in snd_rst_toremote(): %s\n",libnet_geterror(l)); goto err;
		}
	}
	// send RST to remote
	uint8_t flags = TH_RST;
	if (c->ack) flags=TH_RST|TH_ACK;
	if ( (*tcp_ptag = libnet_build_tcp(
											c->sport,c->dport,c->seq+len,c->ack,flags, // add len to seq ?
											0, 0, 0, LIBNET_TCP_H, NULL, 0, l, *tcp_ptag))==-1) {
		ERR("libnet_build_tcp() in snd_rst_toremote(): %s\n", libnet_geterror(l)); goto err;
	}
	if (append_ipheader(c->af, &c->src_addr, &c->dst_addr, l, ip_ptag, 0)==-1) {
		ERR("libnet_build_ip() in snd_rst_toremote(): %s\n", libnet_geterror(l)); goto err;
	}
	// send the packet twice
	if ((libnet_write(l) < 0) || (libnet_write(l) < 0)) {
		WARN("libnet_write() in snd_rst_toremote(): %s\n", libnet_geterror(l));
		//libnet_diag_dump_context(l);
		goto err;
	}
	return 1;
	
err:
	free_libnet(ld); init_libnet(ld);
	return -1;
}

void rst_accept_loop() {
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	size_t res=0;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	init_libnet(&ld_rst);
	sniffers_t sn_rst; memset(&sn_rst,0,sizeof(sniffers_t));
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d (send_rst)...\n", RST_PORT);
		if ((s2 = accept(sock, (struct sockaddr *)&remote, &len)) == -1) {
			ERR("Problem accepting new connection on localhost port %d (send_rst): %s\n", RST_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d (send_rst)\n", RST_PORT);
		if (check_signature(s2, RST_PORT)<0) {
			// couldn't authenticate client
			close(s2);
			continue;
		}
		int pid = get_sock_pid(s2, RST_PORT);
		
		// when UI starts up it creates a connection and keeps it open
		// until it shuts down, so we accept and then keep listening
		// until other side closes (or we get an error).
		for(;;) {
			// read RST packet parameters
			conn_raw_t c;
			
			// before reading data, we recheck client when PID changes
			int current_pid = get_sock_pid(s2, RST_PORT);
			if (current_pid != pid) {
				if (check_signature(s2, RST_PORT)<0) break;
			}
			pid = current_pid;
			int syn;
			if ( (res=readn(s2, &syn, sizeof(int)) )<=0) break;
			//set_recv_timeout(s2, RECV_TIMEOUT); // to be safe, readn() will eventually timeout
			if ( (res=readn(s2, &c.af, sizeof(int)) )<=0) break;
			if ( (res=readn(s2, &c.src_addr, sizeof(struct in6_addr)) )<=0) break;
			if ( (res=readn(s2, &c.sport, sizeof(uint16_t)) )<=0) break;
			if ( (res=readn(s2, &c.dst_addr, sizeof(struct in6_addr)) )<=0) break;
			if ( (res=readn(s2, &c.dport, sizeof(uint16_t)) )<=0) break;
			if ( (res=readn(s2, &c.seq, sizeof(uint32_t)) )<=0) break;
			if ( (res=readn(s2, &c.ack, sizeof(uint32_t)) )<=0) break;
			// nb: data here is formatted for an outgoing connection
			
			char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
			inet_ntop(c.af, &c.src_addr, sn, INET6_ADDRSTRLEN);
			inet_ntop(c.af, &c.dst_addr, dn, INET6_ADDRSTRLEN);
			INFO2("af=%d, sport=%u, dport=%u, ack=%u, seq=%u, %s %s\n",c.af,c.sport,c.dport,c.ack,c.seq,sn,dn);
			
			// do some basic sanity checking
			if (c.af!=AF_INET && c.af!=AF_INET6) continue;

			/* we're sending a RST here in response to receiving a SYN-ACK. example of syn-ack-rst exchange:
			192.168.1.27	54.171.86.180	TCP	55054 → 2000 [SYN] Seq=2730891158 Win=65535 Len=0
			54.171.86.180	192.168.1.27	TCP	2000 → 55054 [SYN, ACK] Seq=614073368 Ack=2730891159 Len=0
			192.168.1.27	54.171.86.180	TCP	55054 → 2000 [ACK] Seq=2730891159 Ack=614073369 Len=0
			54.171.86.180	192.168.1.27	TCP	2000 → 55054 [RST, ACK] Seq=614073369 Ack=2730891159 Len=0
			*/
			// nb: conn details sent to us by client are formatted for an outgoing connection.
			// so c.seq is the ack from the SYN-ACK, c.ack is the seq from the SYN-ACK
			snd_rst_toremote(&c, &ld_rst, 1); // will use c.seq as RST seq number
			// local host has sent an ACK in response to the SYN-ACK, so local host expects remote
			// to use ack number of that ACK in any RST it sends, so we need to increment
			// c.ack (seq from the SYN-ACK) by 1 over value in the SYN-ACK
			c.ack++;
			snd_rst_toself(&c, &ld_rst, NULL);  // will use c.ack as RST seq number
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv() on port %d (send_rst): %s\n",RST_PORT, strerror(errno));
		INFO("Connection closed on port %d (send_rst).\n", RST_PORT);
		close(s2);
	}
}
