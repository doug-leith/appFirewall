//
//  pcap_sniffer.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "pcap_sniffer.h"

//globals
static pcap_t *pd;  // pcap listener
static time_t stats_time; // time when last asked pcap for stats
static int p_sock, p_sock2=-1;
static int pid = -1;
static pthread_t listener_thread; // handle to listener thread

void close_sniffer_sock() {
	close(p_sock); close(p_sock2);
}

bpf_u_int32 start_sniffer(pcap_t **pd, char* filter_exp) {
	// fire up pcap listener ...
	
	char *intf, ebuf[PCAP_ERRBUF_SIZE];
	
	// get network device
	if ((intf = pcap_lookupdev(ebuf)) == NULL) {
		ERR("pcap couldn't find default device: %s", ebuf);
		//EXITFAIL("Problem listening to network: pcap couldn't find default device: %s", ebuf);
		exit(EXIT_FAILURE);
	}
	//INFO("Listening on device: %s\n", intf);
	bpf_u_int32 mask, net;
	if (pcap_lookupnet(intf, &net, &mask, ebuf) == -1) {
		WARN("Can't get netmask for device %s: %s\n", intf, ebuf);
		net = 0;
		mask = 0;
	}
	
	// create pcap listener
	if ((*pd = pcap_create(intf, ebuf)) == NULL) {
		ERR("Couldn't create pcap sniffer %s\n",ebuf);
		exit(EXIT_FAILURE);
	}
	#define SNAPLEN 512 // needs to be big enough to capture dns payload
	if (pcap_set_snaplen(*pd,SNAPLEN)!=0) {
		WARN("Couldn't set snaplen on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	if (pcap_set_immediate_mode(*pd,1)!=0) { // deliver sniffed packets immediately.
		WARN("Couldn't set immediate mode on pcap sniffer: %s\n",pcap_geterr(*pd));
	}
	#define BUFFER_SIZE 2097152*8  // default is 2M=2097152, but we increase it to 16M
	pcap_set_buffer_size(*pd, BUFFER_SIZE);
	
	// try to list tstamp types, returns res=0 in MAC OS Mojave
	/*int *tstamp_types;
	int res = pcap_list_tstamp_types(*pd, &tstamp_types);
	if (res<0) {
		WARN("Couldn't list timestamp types on pcap sniffer: %s\n",pcap_geterr(*pd));
	} else if (res==0) {
		INFO("No timestamp types on pcap sniffer: res=%d\n",res);
	} else {
		for (int i = 0; i<res; i++) {
			INFO("%s (%d) ",pcap_tstamp_type_val_to_name(tstamp_types[i]), tstamp_types[i]);
		}
	}
	pcap_free_tstamp_types(tstamp_types);
	*/
	
	// now that its configured, fire up listener
	if (pcap_activate(*pd)!=0) {
		ERR("Couldn't activate pcap sniffer: %s\n",pcap_geterr(*pd));
		exit(EXIT_FAILURE);
	}
	
	// set the filter ..
	if (filter_exp!=NULL)  {
		struct bpf_program fp;		/* The compiled filter expression */
		if (pcap_compile(*pd, &fp, filter_exp, 0, mask) == -1) {
			ERR("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(*pd, &fp) == -1) {
			ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(*pd));
			exit(EXIT_FAILURE);
		}
	}
		
	// we need to specify the link layer header size.  have hard-wired in
	// ethernet value of 14, so check link we have is compatible with this
	int dl;
	if ( (dl=pcap_datalink(*pd)) != DLT_EN10MB) { //
		ERR("Device %s not supported: %d\n", intf, dl);
		//EXITFAIL("Device %s not supported: %d\n", intf, dl);
		exit(EXIT_FAILURE);
	}
	return mask;
}

void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// send pkt to GUI
	DEBUG2("sniffed pkt, sending to GUI ... %d bytes\n",pkthdr->caplen);
	
	const int pcap_off = 14; // ethernet link layer offset
	int version = (*(pkt + pcap_off))>>4; // get IP version
	u_char* nexth=NULL; // this will point to TCP/UDP header
	if (version == 4) {
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(pkt + pcap_off);
		nexth=((u_char *)ip + (ip->ip_hl * 4));
	} else {
		struct libnet_ipv6_hdr *ip = (struct libnet_ipv6_hdr *)(pkt + pcap_off);
		nexth = ((u_char *)ip + sizeof(struct libnet_ipv6_hdr));
	}
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)nexth;
	int syn = (tcp->th_flags & (TH_SYN)) && !(tcp->th_flags & (TH_ACK));
	if (syn) { signal_dtrace(); return; }
	
	// before sending data, we recheck client when PID changes
	int current_pid = get_sock_pid(p_sock2, PCAP_PORT);
	if (current_pid != pid) {
		if (check_signature(p_sock2, PCAP_PORT)<0) goto err;
	}
	pid = current_pid;
	
	if (send(p_sock2, pkthdr, sizeof(struct pcap_pkthdr),0)<0) goto err;
	if (send(p_sock2, pkt, pkthdr->caplen,0)<0) goto err;

	// periodically log pcap stats ... we don't want to be seeing too many pkt drops
	time_t stats_now = time(NULL);
	if (stats_now-stats_time > 600) {
		struct pcap_stat stats;
		stats_time = stats_now;
		pcap_stats(pd, &stats);
		INFO("pcap stats: recvd=%d, dropped=%d, if_dropped=%d\n",
		stats.ps_recv,stats.ps_drop,stats.ps_ifdrop);
		fflush(stdout);
	}
	return;
	
err:
	WARN("send: %s\n", strerror(errno));
	// likely helper has shut down connection,
	// in any case close socket and exit pcap listening loop
	pcap_breakloop(pd);
	close(p_sock2);
}

void *listener(void *ptr) {
	// wait in accept() loop to handle connections from GUI to receive pcap info
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d ...\n", PCAP_PORT);
		if ((p_sock2 = accept(p_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			ERR("Problem accepting new connection on localhost port %d: %s\n", PCAP_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d\n", PCAP_PORT);
		if (check_signature(p_sock2, PCAP_PORT)<=0) {
			// couldn't authenticate client
			close(p_sock2);
			continue;
		}
		pid = get_sock_pid(p_sock2, PCAP_PORT);
		
		set_snd_timeout(p_sock2, SND_TIMEOUT); // to be safe, send() will eventually timeout

		// now fire up pcap loop, and will send sniffed pkt info acoss link to GUI client,
		// this will exit when network connection fails/is broken.
		stats_time = time(NULL);
		if (pcap_loop(pd, -1,	sniffer_callback, NULL)==PCAP_ERROR){	// this blocks
			ERR("pcap_loop: %s\n", pcap_geterr(pd));
		}
	}
	return NULL;
}

void start_listener() {
	// start listening for requests to receive pcap info
	p_sock = bind_to_port(PCAP_PORT,2);
	INFO("Now listening on localhost port %d\n", PCAP_PORT);

	// tcpflags doesn't work for ipv6, sigh.
	// UDP on ports 443 likely to be quic
	//start_sniffer("(udp and port 53) or (tcp and (tcp[tcpflags]&tcp-syn!=0) || (ip6[6] == 6 && ip6[53]&tcp-syn!=0)) or (udp and port 443)");
	
	// just syn-acks
	/*start_sniffer(&pd, "\
	(udp and port 53) \
	or (tcp and (tcp[tcpflags]&tcp-syn!=0) and (tcp[tcpflags]&tcp-ack!=0)) \
	or (ip6[6] == 6 and (ip6[53]&tcp-syn!=0) and (tcp[tcpflags]&tcp-ack!=0)) \
	or (udp and port 443)");*/
	// syns and syn-acks
	start_sniffer(&pd, "\
	(udp and port 53) \
	or (tcp and (tcp[tcpflags]&tcp-syn!=0)) \
	or (ip6[6] == 6 and (ip6[53]&tcp-syn!=0)) \
	or (udp and port 443)");

	INFO("pcap initialised\n");
	pthread_create(&listener_thread, NULL, listener, NULL);
}

void stop_listener() {
	pthread_kill(listener_thread, SIGTERM);
}
