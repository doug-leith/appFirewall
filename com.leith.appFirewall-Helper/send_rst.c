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
static libnet_data_t ld_rst_remote, ld_rst_toself;
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
	ld->tcp6_ptag=LIBNET_PTAG_INITIALIZER; ld->ip6_ptag=LIBNET_PTAG_INITIALIZER;
	ld->eth_ptag=LIBNET_PTAG_INITIALIZER;

	ld->l4=libnet_init(LIBNET_RAW4,NULL,err_buf);
	if (ld->l4==NULL) {
		ERR("libnet_init() IPv4 failed, won't be able to kill network connections: %s\n", err_buf);
	}
	// we set IP_HDRINCL socket option for this socket, so have to construct
	// full IP header but this allows us to send to self (when not set the
	// kernel constructs source address of header itself)
	// see https://www.unix.com/man-page/osx/8/ip/
	int n = 1;
	if (setsockopt(ld->l4->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n))<0) {
		WARN("libnet setsockopt l4_hdr IP_HDRINCL failed, won't be able to send TCP RST packets to self: %s\n", strerror(errno));
	}
	
	// no IP_HDRINCL option for IPV6 though, sigh
	ld->l6 = NULL; memset(&ld->last_intf,0,sizeof(interface_t)); ld->pd=NULL;
	memset(ld->last_dst_eth,0,ETHER_ADDR_LEN);
}

void free_libnet(libnet_data_t *ld) {
	INFO("free_libnet()\n");
	if (ld->l4) libnet_destroy(ld->l4);
	if (ld->l6) libnet_destroy(ld->l6);
	if (ld->pd) pcap_close(ld->pd);
	memset(ld,0,sizeof(libnet_data_t));
}

libnet_ptag_t append_ether6(libnet_t *l, libnet_ptag_t *eth_ptag, uint8_t eth_src[ETHER_ADDR_LEN], uint8_t eth_dst[ETHER_ADDR_LEN]) {
	// construct link-layer ethernet header, only used for IPv6 packets
	//int i; for(i=0; i<ETHER_ADDR_LEN;i++) printf("%02x ",eth_dst[i]); printf("\n");
	uint8_t tmp[ETHER_ADDR_LEN]; memset(tmp,0,ETHER_ADDR_LEN);
	*eth_ptag = libnet_build_ethernet(
		eth_dst,      				 /* ethernet destination */
		eth_src,     					 /* ethernet source */
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

int setup_ipv6(conn_raw_t* c, interface_t* intf, uint8_t dst_eth[ETHER_ADDR_LEN], libnet_data_t *l){
	// clean up old state
	if (l->l6) {libnet_destroy(l->l6); l->l6 = NULL;}
	if (l->pd) {pcap_close(l->pd); l->pd=NULL;}

	// now initialise
	char err_buf[LIBNET_ERRBUF_SIZE];
	l->l6=libnet_init(LIBNET_LINK,intf->name,err_buf);
	l->tcp6_ptag = LIBNET_PTAG_INITIALIZER; l->ip6_ptag = LIBNET_PTAG_INITIALIZER;
	l->eth_ptag = LIBNET_PTAG_INITIALIZER;

	if (l->l6==NULL) {
		ERR("libnet_init() IPv6 in snd_rst_toself() failed for interface %s, won't be able to kill network connections to self: %s\n", intf->name, err_buf);
		return -1;
	}
	
	//printf("setup_ipv6: %s dlt=%d\n",intf->name,intf->dlt);
	if (intf->dlt == DLT_EN10MB) { // ethernet
		char filter_exp[STR_SIZE];
		// nb: we base pcap filter on ethernet addresses (not IP layer details)
		// so we don't have to keep
		// updating it for every new flow (which is slow).  this means we'll
		// catch too many pkts in filter, but its just used for rough rate
		// limiting so hopefully its good enough.
		char src_eth_str[STR_SIZE], dst_eth_str[STR_SIZE];
		strlcpy(src_eth_str,ether_ntoa((struct ether_addr*)&intf->eth[0]),STR_SIZE);
		strlcpy(dst_eth_str,ether_ntoa((struct ether_addr*)&dst_eth[0]),STR_SIZE);
		snprintf(filter_exp,STR_SIZE,"ip6 and ether dst %s and ether src %s and (ip6[53]&tcp-rst!=0)",dst_eth_str,src_eth_str);
		//printf("pcap filter: %s\n",filter_exp);
		int res=setup_pd(intf, &l->pd, filter_exp, 0);
		if ((res < 0)||(l->pd==NULL)) {
			WARN("Problem in snd_rst_toself() creating sniffer for ethernet interface %s\n",intf->name); return -1;
		}
		pcap_setnonblock(l->pd,1,NULL);
	} else if (intf->dlt == DLT_NULL) {
		// tunnel or loopback
		// TO DO: figure out a decent choice of pcap filter
		int res=setup_pd(intf, &l->pd, "", 0);
		if ((res < 0)||(l->pd==NULL)) {
			WARN("Problem in snd_rst_toself() creating sniffer for DLT_NULL interface %s\n",intf->name); return -1;
		}
		pcap_setnonblock(l->pd,1,NULL);
	} else {
		// shouldn't happen
		WARN("Interface %s is neither ethernet or loopback in snd_rst_toself()\n",intf->name);
		// don't bail here, this means we'll try to use IPv6 without link layer header,
		// if interface doesn't like this (and we're sending LINK_RAW remember with IPv6)
		// then lib_write() will fail and we'll abandon then.
		//return -1;
	}
	return 1;
}

int rst_write(libnet_t *l_hdr, int dlt, pcap_t *pd, int toself) {
	uint32_t len; uint8_t *packet = NULL; ssize_t c;
	if (dlt == -1) {
		// IP layer write, just call libnet to use raw socket
		return libnet_write(l_hdr);
	} else if (dlt == DLT_EN10MB) {
		// ethernet link layer write, contruct the pkt
		if (libnet_write(l_hdr)<0) {
			WARN("Problem doing bpf write to ethernet link layer: %s",libnet_geterror(l_hdr));
			return -1;
		}
	} else if (dlt == DLT_NULL) {
		// likely an IP tunnel, trick libnet into constructing pkt without
		// link layer header.  we can then inject the IP pkt direct at link layer
		l_hdr->injection_type = LIBNET_RAW6;
		if (libnet_pblock_coalesce(l_hdr, &packet, &len)<0) {
			WARN("Problem with DLT_NULL coalesce: %s", libnet_geterror(l_hdr)); return -1;
		}
		l_hdr->injection_type = LIBNET_LINK;
		c = write(l_hdr->fd, packet, len);
		if (l_hdr->aligner > 0) packet = packet - l_hdr->aligner;
		free(packet);
		if (c!=len) {
			WARN("Problem doing bpf write to DLT_NULL link layer: %s (write %zd of %d)", strerror(errno),c,len); return -1;
		}
	} else {
		// some other link layer, wtf?
		return -1;
	}

	// *** link layer rate control ***
	// if we injected pkt at link layer (i.e IPv6) the writes are unbuffered and so
	// we need to do some congestion control to limit rate at which we inject
	// packets.
	
	// write() returns bytes sent. one might
	// suppose that write() < pkt size flags overflow in IPv6
	// link layer pkt injection, but we always
	// get write() == pkt_size even if injected packet is dropped, so resort
	// to pcap feedback approach binstead.  we use pcap to sniff
	// packets and after calling libnet_write()
	// we wait until something appears.
	if (!pd) { // shouldn't happen, but fall back to crude rate limiting
		WARN("In snd_rst() pd=NULL\n");
		usleep(IPV6_SELECT_TIMEOUT);
		return 1;
	}
	int pkts_wanted=1; //if (toself) pkts_wanted=2;
	int pkts_read=0, rtxs=0;
	int fd = pcap_get_selectable_fd(pd);
	while ((pkts_read<pkts_wanted) && (rtxs<2)) {
		fd_set readfds; FD_ZERO(&readfds);FD_SET(fd,&readfds);
		struct timeval timeout;
		timeout.tv_sec = 0; timeout.tv_usec = IPV6_SELECT_TIMEOUT;
		ssize_t res=0, sel_count=0;
		while ( ((res=select(fd+1, &readfds, NULL, NULL, &timeout))<0) && (errno == EINTR) && (sel_count<5) ) sel_count++;
		if (res<0) { // res=0 on timeout, <0 on error
			WARN("snd_rst select: %s\n", strerror(errno));
			break;
		} else if (res==0) { // select timeout.
				// a timeout means that no packet was sniffed, so timeouts are
				// an indicator of loss of injected packets and we'd like to
				// keep the number low
				if (dlt == DLT_EN10MB) libnet_write(l_hdr); //Retransmit
				select_timeouts++; rtxs++;
				//break;
		} else {
				if (FD_ISSET(fd,&readfds)) {
					struct pcap_pkthdr buf; const u_char* ptr;
					while ((ptr=pcap_next(pd, &buf))!=NULL) pkts_read++;
					//printf("read %d pkts from pcap\n", count);
				}
		}
	}
	select_num++; select_count+=pkts_read;
	
	// periodically log stats ... we don't want to be seeing too many
	// timeouts since they likely correspond to link layer losses
	time_t select_now = time(NULL);
	if (select_now-select_time > 10) {//600) {
		select_time = select_now;
		INFO("IPv6 select stats: timeouts=%d (%.2f percent), success=%d (%.2f percent), sniffed pkt count=%d (avg %.2f)\n", select_timeouts, select_timeouts*100.0/(select_timeouts+select_num), select_num, select_num*100.0/(select_timeouts+select_num), select_count, select_count*1.0/select_num);
	}
	return 1;
}

int snd_rst(conn_raw_t* c, libnet_data_t *ld, interface_t* intf, uint8_t dst_eth[ETHER_ADDR_LEN], int num, int try_data) {
	// send RST.  parameter c contains connection details, intf is the outgoing
	// interface to use (can be NULL for IPv4, but needs to be meaningful for IPv6),
	// and dst_eth is the gateway MAC address (again only used for IPv6).  num is
	// number of RSTs to send.
	
	// nb: normally the kernel writes the sender info in packet header itself when we use raw
	// socket. to avoid this with IPv4 we use the IP_HDRINCL socket option.  this option doesn't
	// exist for IPv6 though, so for IPv6 we send via the link layer (what a pointless
	// hassle !)
	// From "man ip6" on macos:
	// "When data received by the kernel are passed to the application, this header is not included in buffer, even when raw sockets are being used.  Likewise, when data are sent to the kernel for transmit from the application, the buffer is not examined for an IPv6 header: the kernel always constructs the header.  To directly access IPv6 headers from received packets and specify them as part of the buffer passed to the kernel, link-level access (bpf(4), for example) must instead be utilized."
	// and the raw socket part says:
	// "Outgoing packets automatically have an IPv6 header prepended to them (based on the destination address and the protocol number the socket was created with). Incoming packets are received by an application without the IPv6 header or any extension headers."
	// it also says "If the proto argument to socket(2) is zero, the default protocol (IPPROTO_RAW) is used for outgoing packets."
	
	// nb2: tried sending IPv6 RSTs to self using lo0 interface rather than en0 (since that's
	// how they're routed for IPV4 (at least that's where tcpdump sniffs them).  but didn't
	// seem to work -- packets are sent ok and can be sniffed using tcpdump, but don't
	// seem to affect flow we're trying to block.

	interface_t temp_intf; memset(&temp_intf,0,sizeof(interface_t));
	temp_intf.dlt = -1; // use raw socket (default for IPv4)

	libnet_ptag_t *tcp_hdr_ptag, *ip_hdr_ptag;
	libnet_t *l_hdr=NULL;
	if (c->af==AF_INET) {// ipv4
		l_hdr = ld->l4; tcp_hdr_ptag=&ld->tcp4_ptag; ip_hdr_ptag=&ld->ip4_ptag;
	} else { // ipv6
		// IPV6 we send to self via link layer.  that means we have to
		// recreate libnet data struct whenever the interface used changes
		// and/or the network gateway MAC address changes
		if (intf==NULL) {
			ERR("snd_rst() called for IPv6 with intf=NULL %s\n",""); return -1;
		}
		memcpy(&temp_intf,intf,sizeof(interface_t));
		if ((ld->l6==NULL) || (ld->pd==NULL) // initial call
				|| (strcmp(ld->last_intf.name,intf->name)!=0) // change in interface being used
				|| (memcmp(ld->last_dst_eth,dst_eth,ETHER_ADDR_LEN)!=0) ){// change in gateway MAC addr
			if (setup_ipv6(c, &temp_intf, dst_eth, ld)<0) goto err;
			// remember link layer details for next time
			memcpy(&ld->last_intf,&temp_intf,sizeof(interface_t));
			memcpy(ld->last_dst_eth,dst_eth,ETHER_ADDR_LEN);
			ld->toself = (memcmp(dst_eth,temp_intf.eth,ETHER_ADDR_LEN)==0);
		}
		l_hdr = ld->l6; tcp_hdr_ptag=&ld->tcp6_ptag; ip_hdr_ptag=&ld->ip6_ptag;
	}
	
	if (l_hdr == NULL) {// shouldn't happen
		WARN("l_hdr==NULL in snd_rst()\n"); goto err;
	}
	
	uint16_t len = 0;
	if (try_data) {
		// this is a bit nasty.  we try to inject data into the connection to
		// generate an error at the remote which will cause it to reset the
		// connection. helpful with VPNs where sending RST to self doesn't work, so
		// getting remote to send RST is useful.
		const char *buf = "drop connection {\n\n\n"; // invalid json and http
		len = (uint16_t)strlen(buf);
		*tcp_hdr_ptag = libnet_build_tcp(c->sport, c->dport, c->seq, c->ack, TH_ACK, 2048, 0, 0, LIBNET_TCP_H, (uint8_t*)buf, len, l_hdr, *tcp_hdr_ptag);
		append_ipheader(c->af, &c->src_addr, &c->dst_addr, l_hdr, ip_hdr_ptag, len);
		if (temp_intf.dlt == DLT_EN10MB) {
			// add ethernet header if required (used for IPv6)
			ld->eth_ptag = append_ether6(l_hdr, &ld->eth_ptag, temp_intf.eth, dst_eth);
		}
		rst_write(l_hdr,temp_intf.dlt,ld->pd,ld->toself);
	}

	uint8_t flags = TH_RST;
	if (c->ack) flags=TH_RST|TH_ACK;
	if ((*tcp_hdr_ptag = libnet_build_tcp(c->sport,c->dport,c->seq,c->ack,flags, //ack+1
																	 0, 0, 0, LIBNET_TCP_H, NULL, 0, l_hdr, *tcp_hdr_ptag))==-1) {
		WARN("libnet_build_tcp() in snd_rst(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (append_ipheader(c->af, &c->src_addr, &c->dst_addr, l_hdr, ip_hdr_ptag, 0)==-1) {
		WARN("libnet_build_ip() in snd_rst(): %s\n", libnet_geterror(l_hdr)); goto err;
	}
	if (temp_intf.dlt == DLT_EN10MB) {
		// add ethernet layer header if required (used for IPv6)
		ld->eth_ptag = append_ether6(l_hdr, &ld->eth_ptag, temp_intf.eth, dst_eth);
		if (ld->eth_ptag<0)  {
			WARN("append_ether6() in snd_rst(): %s\n", libnet_geterror(l_hdr)); goto err;
		}
	}
	
	char sn[INET6_ADDRSTRLEN],dn[INET6_ADDRSTRLEN];
	inet_ntop(c->af, &c->src_addr, sn, INET6_ADDRSTRLEN);
	inet_ntop(c->af, &c->dst_addr, dn, INET6_ADDRSTRLEN);
	DEBUG2("sending %d RST(s) to %s:%d->%s:%d\n",num,sn,c->sport,dn,c->dport);
	int i;
	for (i=0; i< num; i++) {
		if (rst_write(l_hdr,temp_intf.dlt,ld->pd,ld->toself) <= 0) {
			WARN("rst_write() in snd_rst(): %s\n", libnet_geterror(l_hdr)); goto err;
		}
	}
	return 1;
err:
	free_libnet(ld); init_libnet(ld);
	return -1;
}

int snd_rst_toself(conn_raw_t* c, libnet_data_t *ld, interface_t* intf) {
	// details in c are for an outgoing connection
	conn_raw_t cc;
	cc.af = c->af;
	cc.src_addr = c->dst_addr; cc.dst_addr = c->src_addr;
	cc.sport = c->dport; cc.dport = c->sport;
	//rfc793: If the incoming segment has an ACK field, the reset takes its
	//sequence number from the ACK field of the segment, otherwise the
	//reset has sequence number zero and the ACK field is set to the sum
	//of the sequence number and segment length of the incoming segment.
	// -- second case is mainly for SYNs since SYN-ACKs have ACK field
	// and response to an invalid RST is to send an ACK
	cc.seq= c->ack; cc.ack = c->seq;
	if (c->af == AF_INET6) {
		if (intf==NULL) {
			ERR("snd_rst_toself() called with intf=NULL %s\n",""); return -1;
		}
		if (strlen(intf->name)==0) {
			// caller wants us to figure out which interface to use ourselves
			if (!find_intf(c, intf)) {
				char sn[INET6_ADDRSTRLEN],dn[INET6_ADDRSTRLEN];
				inet_ntop(c->af, &c->src_addr, sn, INET6_ADDRSTRLEN);
				inet_ntop(c->af, &c->dst_addr, dn, INET6_ADDRSTRLEN);
				WARN("snd_rst_toself(): couldn't find interface for %s->%s\n",sn,dn);
				return -1;
			}
		}
		// test
		//strcpy(intf->name,"lo0"); intf->dlt = DLT_NULL;
	}
	// send one RST pkt to self
	return snd_rst(&cc,ld,intf,intf->eth,1,0);
}

int snd_rst_toremote(conn_raw_t* c, libnet_data_t *ld, interface_t* intf, int try_data) {
	uint8_t dst_eth[ETHER_ADDR_LEN]; memset(dst_eth,0,ETHER_ADDR_LEN);
	if (c->af == AF_INET6) {
		if (strlen(intf->name)==0) {
			// caller wants us to figure out which interface to use ourselves
			if (!find_intf(c, intf)) {
				char sn[INET6_ADDRSTRLEN],dn[INET6_ADDRSTRLEN];
				inet_ntop(c->af, &c->src_addr, sn, INET6_ADDRSTRLEN);
				inet_ntop(c->af, &c->dst_addr, dn, INET6_ADDRSTRLEN);
				WARN("snd_rst_toremote(): couldn't find interface for %s->%s\n",sn,dn);
				return -1;
			}
		}
		//struct timeval start; gettimeofday(&start, NULL);
		// this call takes about 0.3ms, but we don't send to remote hosts v frequently
		if (!get_default_gateway_eth(c->af,dst_eth)) return -1;
		struct timeval end; gettimeofday(&end, NULL);
		//printf("gw t=%f\n", (end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0);
		//print_eth(dst_eth);
	}
	// send 2 RST pkts (in case of loss) to remote from interface intf via gateway with
	// MAC address dst_eth (only need intf and dst_addr for IPv6)
	return snd_rst(c,ld,intf,dst_eth,2,try_data);

}

void rst_accept_loop() {
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	size_t res=0;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	init_libnet(&ld_rst_remote); init_libnet(&ld_rst_toself);
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
			interface_t intf; memset(&intf,0,sizeof(interface_t));
			snd_rst_toremote(&c, &ld_rst_remote, &intf, 1); // will use c.seq as RST seq number
			// snd_rst_toremote() call will have set intf to have right details,
			// so this setup cost is not duplicated again with this next call.
			snd_rst_toself(&c, &ld_rst_toself, &intf);  // will use c.ack as RST seq number
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv() on port %d (send_rst): %s\n",RST_PORT, strerror(errno));
		INFO("Connection closed on port %d (send_rst).\n", RST_PORT);
		close(s2);
	}
}
