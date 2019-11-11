//
//  appFirewall-Helper
//	- raw socket handler for appFirewall, needs root priviledge
//
// SMJobBless() installs appFirewall-Helper to /Library/PrivilegedHelperTools/
// The steps to get SMJobBless() to work:
// 1. Helper's launch.plist must include label entry with identifier of this helper
//		i.e. com.leith.appFirewall-Helper
// 2. Helper's Info.plist must contain "Clients allowed to add and remove tool" entry
//    with main appFirewall app's identifier
// 3. Main appFirewall's Info.plist must contain "Tools owned after installation" entry
//    pointing to this helper app com.leith.appFirewall-Helper
// 4. And the secret/non-documented step:  add the following linker options to
//	 	com.leith.appFirewall-Helper:
//		-sectcreate __TEXT __info_plist com.leith.appFirewall-Helper/Info.plist
//		-sectcreate __TEXT __launchd_plist com.leith.appFirewall-Helper/launchd.plist
//		which embed the plist files into the com.leith.appFirewall-Helper executable
// 5. Last step: main appFirewall app must copy com.leith.appFirewall-Helper executable
//		to Contents/Library/LaunchServices folder within the app bundle
//
// See https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless

// TCP header details: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_timestamps
// libnet tutorials: https://repolinux.wordpress.com/2011/09/18/libnet-1-1-tutorial/#receiving-packets
//https://repolinux.wordpress.com/category/libnet/#sending-multiple-packets
// libnet source: https://github.com/libnet/libnet
// RFC on RST attack mitigations: https://tools.ietf.org/html/rfc5961#section-3.2

// TO DO:
// - Encrypt TCP connection ?
// - Add some authentication ?

#include <stdio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pcap.h>
#include <pthread.h>
#include "libnet.h"

#define RST_PORT 2
#define PCAP_PORT 3
#define LOGFILE "/Library/Logs/appFirewall-Helper.log"

//globals
static pcap_t *pd;  // pcap listener
static pthread_t thread; // handle to listener thread
static int p_sock, p_sock2=-1;
libnet_t *l4=NULL, *l6 = NULL;  // libnet state
libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag;
static time_t stats_time; // time when last asked pcap for stats

const static int verbose=1;          // debugging level
// apple logging to system.log
#include <os/log.h>
#define ERR_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define WARN_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define INFO_LOG(fmt, ...)  do{if (verbose) os_log(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)

#define ERR(fmt,args ...) do{fprintf(stderr,"%s ERROR: ",now()); fprintf(stdout, fmt,args); os_log_error(OS_LOG_DEFAULT,fmt,args);}while(0)
#define WARN(args ...) do{fprintf(stderr,"%s WARNING: ",now()); fprintf(stdout, args);}while(0)
#define INFO(args ...) if (verbose) do{fprintf(stdout, "%s: ",now());fprintf(stdout, args);}while(0)
#define DEBUG2(args ...) if (verbose>1) fprintf(stdout, args)

char* now() {
	// returns string with current time
	time_t t;
	time(&t);
	char* str=asctime(localtime(&t));
	str[strlen(str)-1]=0; // remove "\n"
	return str;
}

void sigterm_handler(int signum) {
	INFO("signal %d received.\n", signum); // shouldn't really printf() in signal handler
	exit(EXIT_SUCCESS);
}

int readn(int fd, void* buf, int n) {
 // read n bytes from socket fd
	int res=0, posn=0;;
	while (posn<n) {
		res = (int)recv(fd, buf+posn, n-res, 0);
		if (res <= 0) {
			return res;
		}
		posn+=res;
	}
	return posn;
}

void start_sniffer(char* filter_exp) {
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
	// args are: char *device, int snaplen, int promisc, int to_ms, char *ebuf
	// nb: to_ms defines reader timeout, snaplen is #bytes kept for each pkt sniffed
	#define SNAPLEN 512 // needs to be big enough to capture dns payload
	#define TIMEOUT 1
	if ((pd = pcap_open_live(intf, SNAPLEN, 0, TIMEOUT, ebuf)) == NULL) {
		ERR("Couldn't initialize pcap sniffer %s\n",ebuf);
		//EXITFAIL("Couldn't initialize pcap sniffer %s\n",ebuf);
		exit(EXIT_FAILURE);
	}
	
	#define BUFFER_SIZE 2097152*8  // default is 2M=2097152, but we increase it to 16M
	pcap_set_buffer_size(pd, BUFFER_SIZE);
	
	// set the filter ..
	struct bpf_program fp;		/* The compiled filter expression */
	if (pcap_compile(pd, &fp, filter_exp, 0, mask) == -1) {
		ERR("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(pd));
		//EXITFAIL("Couldn't parse pcap filter %s: %s\n", filter_exp, pcap_geterr(pd));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pd, &fp) == -1) {
		ERR("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(pd));
		//EXITFAIL("Couldn't install pcap filter %s: %s\n", filter_exp, pcap_geterr(pd));
		exit(EXIT_FAILURE);
	}
	
	// we need to specify the link layer header size.  have hard-wired in
	// ethernet value of 14, so check link we have is compatible with this
	int dl;
	if ( (dl=pcap_datalink(pd)) != DLT_EN10MB) { //
		ERR("Device %s not supported: %d\n", intf, dl);
		//EXITFAIL("Device %s not supported: %d\n", intf, dl);
		exit(EXIT_FAILURE);
	}
}

void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) {
	// send pkt to GUI
	DEBUG2("sniffed pkt, sending to GUI ... %d bytes\n",pkthdr->caplen);
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

int bind_to_port(int port) {
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		ERR("Problem creating socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int yes=1;
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) == -1) {
		ERR("Setsockopt: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = inet_addr("127.0.0.1");;
	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
		ERR("Problem binding to localhost port %d: %s\n", port, strerror(errno));
		exit(EXIT_FAILURE);
	}
	// we use a small listen queue since we only expect one connection (from GUI)
	// at a time.  attempts at connecting while that connection is ongoing should
	// therefore be refused (they shouldn't even occur).
	if (listen(sock, 2) == -1) {
		ERR("Problem listening to localhost port %d: %s\n", port, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return sock;
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
	// tcpflags doesn't work for ipv6, sigh.
	// UDP on ports 443 likely to be quic
	start_sniffer("(udp and port 53) or (tcp and (tcp[tcpflags]&tcp-syn!=0) || (ip6[6] == 6 && ip6[53]&tcp-syn!=0)) or (udp and port 443)");
	INFO("pcap initialised\n");
	pthread_create(&thread, NULL, listener, NULL);
}

void stop_listener() {
	pthread_kill(thread, SIGTERM);
}

void init_libnet() {
	// now initialise libnet packet processing data structure
	char err_buf[LIBNET_ERRBUF_SIZE];
	
	tcp4_ptag=LIBNET_PTAG_INITIALIZER;
	ip4_ptag=LIBNET_PTAG_INITIALIZER;
	tcp6_ptag=LIBNET_PTAG_INITIALIZER;
	ip6_ptag=LIBNET_PTAG_INITIALIZER;

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
}

int main(int argc, char *argv[]) {

	#pragma unused(argc)
	#pragma unused(argv)

	// set up logging
	int logfd = open(LOGFILE,O_RDWR|O_CREAT|O_APPEND,0644);
	if (logfd == -1) {
		ERR("Failed to open logfile: %s\n",strerror(errno));
		//exit(EXIT_FAILURE);
	}
	dup2(logfd,STDOUT_FILENO); // redirect stdout to log file
	dup2(logfd,STDERR_FILENO); // ditto stderr
	close(logfd);
	setbuf(stdout, NULL); // disable buffering on stdout, to save calling fflush()

	INFO("appFilter-Helper started.\n");

	// set up SIGTERM handler
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigterm_handler;
	sigaction(SIGTERM, &action, NULL);

	// and disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);
	
	// now initialise libnet packet processing data structure
	init_libnet();
	
	INFO("libnet initialised\n");
	
	// start listening for commands to send RST packets
	int sock = bind_to_port(RST_PORT);
	INFO("Now listening on localhost port %d\n", RST_PORT);

	// start listening for requests to receive pcap info
	p_sock = bind_to_port(PCAP_PORT);
	INFO("Now listening on localhost port %d\n", PCAP_PORT);
	
	// once we get this far any errors are treated as non-fatal i.e.
	// won't kill process but instead will try to repair things
	
	start_listener();
	INFO("pcap listener started\n");

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
			DEBUG2("af=%d, sport=%d, dport=%d, ack=%d, seq=%d, %s %s\n",af,sport,dport,ack,seq,sn,dn);
			
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
			// construct tcp header for RST pkt
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
			
			// construct IP header for RST packet
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
			}
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv(): %s\n",strerror(errno));
		INFO("Connection closed on port %d.\n", RST_PORT);
		close(s2);
	}
}
