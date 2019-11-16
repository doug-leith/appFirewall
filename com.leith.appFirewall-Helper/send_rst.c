//
//  send_rst.c
//  com.leith.appFirewall-Helper
//

#include "send_rst.h"

//globals
static libnet_t *l4=NULL, *l6 = NULL, *l4_hdr = NULL, *l6_hdr=NULL;  // libnet state
static libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, tcp4_hdr_ptag, ip4_hdr_ptag,tcp6_hdr_ptag, ip6_hdr_ptag;
static int sock;

void init_libnet() {
	// now initialise libnet packet processing data structure
	char err_buf[LIBNET_ERRBUF_SIZE];
	
	tcp4_ptag=LIBNET_PTAG_INITIALIZER; ip4_ptag=LIBNET_PTAG_INITIALIZER;
	tcp4_hdr_ptag=LIBNET_PTAG_INITIALIZER; ip4_hdr_ptag=LIBNET_PTAG_INITIALIZER;
	tcp6_ptag=LIBNET_PTAG_INITIALIZER; ip6_ptag=LIBNET_PTAG_INITIALIZER;
	tcp6_hdr_ptag=LIBNET_PTAG_INITIALIZER; ip6_hdr_ptag=LIBNET_PTAG_INITIALIZER;

	l4=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (l4==NULL) {
		ERR("libnet_init() IPv4 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	l6=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (l6==NULL) {
		ERR("libnet_init() IPv6 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	
	// we set IP_HDRINCL socket option for this socket, so have to construct full
	// IP header but this allows us to send to self (when not set the kernel
	// constructs source part of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	l4_hdr=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (l4_hdr==NULL) {
		ERR("libnet_init() IPv4 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	int n = 1;
	if (setsockopt(l4_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt IP_HDRINCL failed: %s", strerror(errno));
	}
	
	l6_hdr=libnet_init(LIBNET_RAW6,NULL,err_buf);
	if (l6_hdr==NULL) {
		ERR("libnet_init() IPv6 failed: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}
	if (setsockopt(l6_hdr->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		ERR("setsockopt IP_HDRINCL failed: %s", strerror(errno));
	}

	// start listening for commands to send RST packets
	sock = bind_to_port(RST_PORT);
	INFO("Now listening on localhost port %d\n", RST_PORT);

}

void rst_accept_loop() {
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	int res, s2;
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
			uint16_t af, dport, sport;
			uint32_t ack, seq;
			struct in6_addr src,dst;
			if ( (res=readn(s2, &af, sizeof(int)) )<=0) break;			
			if ( (res=readn(s2, &src, sizeof(struct in6_addr)) )<=0) break;
			if ( (res=readn(s2, &sport, sizeof(uint16_t)) )<=0) break;
			if ( (res=readn(s2, &dst, sizeof(struct in6_addr)) )<=0) break;
			if ( (res=readn(s2, &dport, sizeof(uint16_t)) )<=0) break;
			if ( (res=readn(s2, &seq, sizeof(uint32_t)) )<=0) break;
			if ( (res=readn(s2, &ack, sizeof(uint32_t)) )<=0) break;
						
			char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
			inet_ntop(af, &src, sn, INET6_ADDRSTRLEN);
			inet_ntop(af, &dst, dn, INET6_ADDRSTRLEN);
			INFO("af=%d, sport=%d, dport=%d, ack=%d, seq=%d, %s %s\n",af,sport,dport,ack,seq,sn,dn);
			
			// do some basic sanity checking
			if (af!=AF_INET && af!=AF_INET6) continue;

			libnet_t *l=NULL;
			libnet_ptag_t *tcp_ptag, *ip_ptag;
			// construct and send the RST packet
			if (af==AF_INET) {
				// ipv4
				l = l4;
				tcp_ptag=&tcp4_ptag; ip_ptag=&ip4_ptag;
			} else {
				// ipv6
				l= l6;
				tcp_ptag=&tcp6_ptag; ip_ptag=&ip6_ptag;
			}
			// construct tcp header for RST pkt to remote host
			uint8_t flags=TH_RST;
			*tcp_ptag = libnet_build_tcp(sport,dport,seq,ack,flags,
																	0, 0, 0, LIBNET_TCP_H, NULL, 0, l, *tcp_ptag);
			if(*tcp_ptag == -1) {
				// should never happen
				ERR("libnet_build_tcp(): %s\n", libnet_geterror(l));
				libnet_destroy(l);
				//exit(EXIT_FAILURE);
				// try to repair the error
				init_libnet();
				continue;
			}
			
			// construct IP header for RST packet to remote host
			if (af==AF_INET) {
				uint32_t d,s;
				memcpy(&s,&src.s6_addr,4);
				memcpy(&d,&dst.s6_addr,4);
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
				memcpy(&s,&src,16);
				memcpy(&d,&dst,16);
				*ip_ptag = libnet_build_ipv6(0,0,0,
																		IPPROTO_TCP,64,
																		s, d,
																		NULL, 0, l, *ip_ptag);
			}
			
			if(*ip_ptag == -1) {
				// should never happen
				ERR("libnet_build %s\n", libnet_geterror(l));
				libnet_destroy(l);
				//exit(EXIT_FAILURE);
				// try to repair the error
				init_libnet();
				continue;
			}
			
			// and send  the packet
			if (libnet_write(l) < 0) {
				// problem writing to raw socket
				WARN("libnet_write() %s\n", libnet_geterror(l));
			} else {
				// and send again, in case first one is lost
				if (libnet_write(l) < 0) {
					// problem writing to raw socket
					WARN("libnet_write() %s\n", libnet_geterror(l));
				}
			}
			
			if (af==AF_INET) {
				// now construct TCP RST packet to send to self
				// construct tcp header for RST pkt to remote host
				uint8_t flags=TH_RST;
				tcp4_hdr_ptag = libnet_build_tcp(dport,sport,ack+1,seq,flags,
																	0, 0, 0, LIBNET_TCP_H, NULL, 0, l4_hdr, tcp4_hdr_ptag);
				uint32_t d,s;
				memcpy(&s,&src.s6_addr,4);
				memcpy(&d,&dst.s6_addr,4);
				ip4_hdr_ptag = libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H,
																	0, 0, 0, 64, IPPROTO_TCP,0,
																	d, s,
																	NULL, 0, l4_hdr, ip4_hdr_ptag);
				if (libnet_write(l4_hdr) < 0) {
					// problem writing to raw socket
					WARN("libnet_write() l4_hdr %s\n", libnet_geterror(l));
				}
			} else {
				uint8_t flags=TH_RST;
				tcp6_hdr_ptag = libnet_build_tcp(dport,sport,ack+1,seq,flags,
																	0, 0, 0, LIBNET_TCP_H, NULL, 0, l6_hdr, tcp6_hdr_ptag);
				struct libnet_in6_addr s, d;
				memcpy(&s,&src,16);
				memcpy(&d,&dst,16);
				ip6_hdr_ptag = libnet_build_ipv6(0,0,0,
																		IPPROTO_TCP,64,
																		d, s,
																		NULL, 0, l6_hdr, ip6_hdr_ptag);
				if (libnet_write(l6_hdr) < 0) {
					// problem writing to raw socket
					WARN("libnet_write() l6_hdr %s\n", libnet_geterror(l));
				}
			}
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv() on port %d: %s\n",RST_PORT, strerror(errno));
		INFO("Connection closed on port %d.\n", RST_PORT);
		close(s2);
	}
}
