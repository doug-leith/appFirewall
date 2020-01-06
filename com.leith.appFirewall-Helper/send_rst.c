//
//  send_rst.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "send_rst.h"

// nice info on raw sockets: https://sock-raw.org/papers/sock_raw
 
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
	INFO("Now listening on localhost port %d (send_rst)\n", RST_PORT);
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
		ERR("libnet_init() IPv4 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	ld->l6=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (ld->l6==NULL) {
		ERR("libnet_init() IPv6 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	
	// we set IP_HDRINCL socket option for this socket, so have to construct
	// full IP header but this allows us to send to self (when not set the
	// kernel constructs source part of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	ld->l4_hdr=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4_hdr==NULL) {
		ERR("libnet_init() IPv4 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	int n = 1;
	if (setsockopt(ld->l4_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		WARN("libnet setsockopt IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}
	
	ld->l6_hdr=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (ld->l6_hdr==NULL) {
		ERR("libnet_init() IPv6 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	
	n = 1;
	if (setsockopt(ld->l6_hdr->fd, IPPROTO_IPV6, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt() IPv6 IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}

}

void free_libnet(libnet_data_t *ld) {
	INFO("free_libnet()\n");
	if (ld->l4) libnet_destroy(ld->l4);
	if (ld->l6) libnet_destroy(ld->l6);
	if (ld->l4_hdr) libnet_destroy(ld->l4_hdr);
	if (ld->l6_hdr) libnet_destroy(ld->l6_hdr);
}

libnet_ptag_t append_ipheader(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr, libnet_t *l, libnet_ptag_t *ip_ptag, uint16_t len) {
	// construct IP header for RST packet to remote host
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
		*ip_ptag = libnet_build_ipv6(0,0,LIBNET_TCP_H,
																 IPPROTO_TCP, 64,
																 s, d,
																 NULL, 0, l, *ip_ptag);
	}
	return *ip_ptag;
}

int snd_rst(int syn, conn_raw_t* c, int onlyself, libnet_data_t *ld) {

	// send RSTs to specified connection
	libnet_ptag_t *tcp_ptag, *ip_ptag, *tcp_hdr_ptag, *ip_hdr_ptag;
	libnet_t *l=NULL, *l_hdr=NULL;
	if (c->af==AF_INET) {// ipv4
		l = ld->l4; tcp_ptag=&ld->tcp4_ptag; ip_ptag=&ld->ip4_ptag;
		l_hdr = ld->l4_hdr; tcp_hdr_ptag=&ld->tcp4_hdr_ptag; ip_hdr_ptag=&ld->ip4_hdr_ptag;
	} else { // ipv6
		l= ld->l6; tcp_ptag=&ld->tcp6_ptag; ip_ptag=&ld->ip6_ptag;
		l_hdr = ld->l6_hdr; tcp_hdr_ptag=&ld->tcp6_hdr_ptag; ip_hdr_ptag=&ld->ip6_hdr_ptag;
	}
	
	if (!syn && !onlyself && (l!=NULL)) {
		// this is a bit nasty.  we try to inject data into the connection to
		// generate an error at the remote which will cause it to reset the
		// connection. helpful with VPNs where sending RST to self doesn't work, so
		// getting remote to send RST is good.
		const char *buf = "drop connection {\n\n\n"; // invalid json and http
		uint16_t len = (uint16_t)strlen(buf);
		*tcp_ptag = libnet_build_tcp(
		c->sport,c->dport,c->seq,c->ack,TH_ACK,
		4096, 0, 0, LIBNET_TCP_H, (uint8_t*)buf, len, l, *tcp_ptag);
		append_ipheader(c->af, &c->src_addr, &c->dst_addr, l, ip_ptag, len);
		if (libnet_write(l)==-1) {
			WARN("data %s\n",libnet_geterror(l));
		}
	
		// send RST to remote
		uint8_t flags=TH_RST;
		if ( (*tcp_ptag = libnet_build_tcp(
												c->sport,c->dport,c->seq+len,c->ack,flags,
												0, 0, 0, LIBNET_TCP_H, NULL, 0, l, *tcp_ptag))==-1) {
			ERR("libnet_build_tcp(): %s\n", libnet_geterror(l)); goto err;
		}
		if (append_ipheader(c->af, &c->src_addr, &c->dst_addr, l, ip_ptag, 0)==-1) {
			ERR("libnet_build_ip() %s\n", libnet_geterror(l)); goto err;
		}
		
		// send the packet twice
		if ((libnet_write(l) < 0) || (libnet_write(l) < 0)) {
			WARN("libnet_write() %s\n", libnet_geterror(l));
			//libnet_diag_dump_context(l);
			goto err;
		}
		
	} // end !syn && !self
	
	if (l_hdr == NULL) goto err; // shouldn't happen
	// send RST to self.  fails with VPNs (at least with openVPN as it
	// messes up packets sent to self).
	// nb: needs IP_HDRINCL to be set for this to work
	uint8_t flags=TH_RST;
	if ((*tcp_hdr_ptag = libnet_build_tcp(c->dport,c->sport,c->ack+1,c->seq,flags,
																	 0, 0, 0, LIBNET_TCP_H, NULL, 0, l_hdr, *tcp_hdr_ptag))==-1) {
		ERR("libnet_build_tcp_hdr(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (append_ipheader(c->af, &c->dst_addr, &c->src_addr, l_hdr, ip_hdr_ptag, 0)==-1) {
		ERR("libnet_build_ip_hdr() %s\n", libnet_geterror(l)); goto err;
	}
	if (libnet_write(l_hdr) < 0) {
		// problem writing to raw socket
		WARN("libnet_write() l_hdr %s\n", libnet_geterror(l_hdr)); goto err;
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
		if (res<0) WARN("recv() on port %d (send_rst): %s\n",RST_PORT, strerror(errno));
		INFO("Connection closed on port %d (send_rst).\n", RST_PORT);
		close(s2);
	}
}
