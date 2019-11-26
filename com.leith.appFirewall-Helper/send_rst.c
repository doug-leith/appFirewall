//
//  send_rst.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "send_rst.h"

//globals
static int sock, s2;
static libnet_data_t ld_rst;

void close_rst_sock() {
	close(sock); close(s2);
}

void start_libnet() {
	init_libnet(&ld_rst);
	// start listening for commands to send RST packets
	sock = bind_to_port(RST_PORT,2);
	INFO("Now listening on localhost port %d\n", RST_PORT);
}

void init_libnet(libnet_data_t *ld) {
	// now initialise libnet packet processing data structure
	char err_buf[LIBNET_ERRBUF_SIZE];
	
	INFO("init_libnet\n");
	
	ld->tcp4_ptag=LIBNET_PTAG_INITIALIZER; ld->ip4_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp4_hdr_ptag=LIBNET_PTAG_INITIALIZER; ld->ip4_hdr_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp6_ptag=LIBNET_PTAG_INITIALIZER; ld->ip6_ptag=LIBNET_PTAG_INITIALIZER;
	ld->tcp6_hdr_ptag=LIBNET_PTAG_INITIALIZER; ld->ip6_hdr_ptag=LIBNET_PTAG_INITIALIZER;

	ld->l4=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4==NULL) {
		ERR("libnet_init() IPv4 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	ld->l6=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (ld->l6==NULL) {
		ERR("libnet_init() IPv6 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	
	// we set IP_HDRINCL socket option for this socket, so have to construct full
	// IP header but this allows us to send to self (when not set the kernel
	// constructs source part of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	ld->l4_hdr=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4_hdr==NULL) {
		ERR("libnet_init() IPv4 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	int n = 1;
	if (setsockopt(ld->l4_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt IP_HDRINCL failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	ld->l6_hdr=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (ld->l6_hdr==NULL) {
		ERR("libnet_init() IPv6 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	// doesn't seem to work for IPv6, sigh
	/*if (setsockopt(l6_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt IP_HDRINCL failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}*/

}

void free_libnet(libnet_data_t *ld) {
	INFO("free_libnet()\n");
	libnet_destroy(ld->l4);
	libnet_destroy(ld->l6);
	libnet_destroy(ld->l4_hdr);
	libnet_destroy(ld->l6_hdr);
}

void snd_rst(int syn, conn_raw_t* c, int onlyself, libnet_data_t *ld) {

	// send RSTs to specified connection
	libnet_t *l=NULL;
	libnet_ptag_t *tcp_ptag, *ip_ptag;
	if (!syn && !onlyself) {
		
		// construct and send the RST packet to remote
		if (c->af==AF_INET) {
			// ipv4
			l = ld->l4;
			tcp_ptag=&ld->tcp4_ptag; ip_ptag=&ld->ip4_ptag;
		} else {
			// ipv6
			l= ld->l6;
			tcp_ptag=&ld->tcp6_ptag; ip_ptag=&ld->ip6_ptag;
		}
		// construct tcp header for RST pkt to remote host
		uint8_t flags=TH_RST;
		*tcp_ptag = libnet_build_tcp(c->sport,c->dport,c->seq,c->ack,flags,
																 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, *tcp_ptag);
		if(*tcp_ptag == -1) {
			// should never happen
			ERR("libnet_build_tcp(): %s\n", libnet_geterror(l));
			free_libnet(ld);
			// try to repair the error
			init_libnet(ld);
			return;
		}
		
		// construct IP header for RST packet to remote host
		if (c->af==AF_INET) {
			uint32_t d,s;
			memcpy(&s,&c->src_addr.s6_addr,4);
			memcpy(&d,&c->dst_addr.s6_addr,4);
			//libnet_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,
			//uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,
			//const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
			*ip_ptag = libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H,
																	 0, 0, 0, 64, IPPROTO_TCP,0,
																	 s, d,
																	 NULL, 0, l, *ip_ptag);
		} else {
			//libnet_build_ipv6(uint8_t tc, uint32_t fl, uint16_t len, uint8_t nh,
			//uint8_t hl, struct libnet_in6_addr src, struct libnet_in6_addr dst,
			//const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
			struct libnet_in6_addr s, d;
			memcpy(&s,&c->src_addr,16);
			memcpy(&d,&c->dst_addr,16);
			*ip_ptag = libnet_build_ipv6(0,0,0,
																	 IPPROTO_TCP,64,
																	 s, d,
																	 NULL, 0, l, *ip_ptag);
		}
		
		if(*ip_ptag == -1) {
			// should never happen
			ERR("libnet_build %s\n", libnet_geterror(l));
			free_libnet(ld);
			// try to repair the error
			init_libnet(ld);
			return;
		}
		
		// and send the packet
		if (libnet_write(l) < 0) {
			// problem writing to raw socket
			WARN("libnet_write() %s\n", libnet_geterror(l));
			libnet_diag_dump_context(l);
			free_libnet(ld);
			// try to repair
			init_libnet(ld);
			return;
		} else {
			// and send again, in case first one is lost
			if (libnet_write(l) < 0) {
				// problem writing to raw socket
				WARN("libnet_write2() %s\n", libnet_geterror(l));
				free_libnet(ld);
				// try to repair
				init_libnet(ld);
				return;
			}
		}
		
	} // end !syn && ! self
	
	if (c->af==AF_INET) {
		// now construct TCP RST packet to send to self
		// construct tcp header for RST pkt to remote host
		uint8_t flags=TH_RST;
		if (syn) { // for a SYN we need to set ack flag in RST
			flags |= TH_ACK;
			ld->tcp4_hdr_ptag = libnet_build_tcp(c->dport,c->sport,0,c->seq+1,flags,
																			 0, 0, 0, LIBNET_TCP_H, NULL, 0, ld->l4_hdr, ld->tcp4_hdr_ptag);
		} else { // otherwise no need for ack'ing, its only the seq number that matters
			ld->tcp4_hdr_ptag = libnet_build_tcp(c->dport,c->sport,c->ack+1,c->seq,flags,
																			 0, 0, 0, LIBNET_TCP_H, NULL, 0, ld->l4_hdr, ld->tcp4_hdr_ptag);
			//printf("sending rst to self: sport=%u, dport=%u, seq=%u, ack=%u\n",c->dport,c->sport,c->ack+1,c->seq);
		}
		uint32_t d,s;
		memcpy(&s,&c->src_addr.s6_addr,4);
		memcpy(&d,&c->dst_addr.s6_addr,4);
		ld->ip4_hdr_ptag = libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H,
																		 0, 0, 0, 64, IPPROTO_TCP,0,
																		 d, s,
																		 NULL, 0, ld->l4_hdr, ld->ip4_hdr_ptag);
		if (libnet_write(ld->l4_hdr) < 0) {
			// problem writing to raw socket
			WARN("libnet_write() l4_hdr %s\n", libnet_geterror(ld->l4_hdr));
			libnet_diag_dump_context(ld->l4_hdr);
			free_libnet(ld);
			// try to repair
			init_libnet(ld);
			return;
		}
	} else {
		// can't set IP_HDRINCL flag for IPv6, will this even work ?
		uint8_t flags=TH_RST;
		if (syn) flags |= TH_ACK;
		ld->tcp6_hdr_ptag = libnet_build_tcp(c->dport,c->sport,c->ack+1,c->seq,flags,
																		 0, 0, 0, LIBNET_TCP_H, NULL, 0, ld->l6_hdr, ld->tcp6_hdr_ptag);
		struct libnet_in6_addr s, d;
		memcpy(&s,&c->src_addr,16);
		memcpy(&d,&c->dst_addr,16);
		ld->ip6_hdr_ptag = libnet_build_ipv6(0,0,0,
																		 IPPROTO_TCP,64,
																		 d, s,
																		 NULL, 0, ld->l6_hdr, ld->ip6_hdr_ptag);
		if (libnet_write(ld->l6_hdr) < 0) {
			// problem writing to raw socket
			WARN("libnet_write() l6_hdr %s\n", libnet_geterror(ld->l6_hdr));
			free_libnet(ld);
			// try to repair
			init_libnet(ld);
			return;
		}
	}
	
}

void rst_accept_loop() {
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	int res;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d ...\n", RST_PORT);
		if ((s2 = accept(sock, (struct sockaddr *)&remote, &len)) == -1) {
			ERR("Problem accepting new connection on localhost port %d: %s\n", RST_PORT, strerror(errno));
			continue;
		}
		
		INFO("Started new connection on port %d\n", RST_PORT);
		
		// when UI starts up it creates a connection and keeps it open
		// until it shuts down, so we accept and then keep listening
		// until other side closes (or we get an error).
		for(;;) {
			// read RST packet parameters
			conn_raw_t c;
			
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
			
			char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
			inet_ntop(c.af, &c.src_addr, sn, INET6_ADDRSTRLEN);
			inet_ntop(c.af, &c.dst_addr, dn, INET6_ADDRSTRLEN);
			INFO2("af=%d, sport=%u, dport=%u, ack=%u, seq=%u, %s %s\n",c.af,c.sport,c.dport,c.ack,c.seq,sn,dn);
			
			// do some basic sanity checking
			if (c.af!=AF_INET && c.af!=AF_INET6) continue;
			
			snd_rst(syn, &c, 0, &ld_rst);
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv() on port %d: %s\n",RST_PORT, strerror(errno));
		INFO("Connection closed on port %d.\n", RST_PORT);
		close(s2);
	}
}
