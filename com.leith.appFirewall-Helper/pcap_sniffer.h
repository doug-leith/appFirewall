//
//  pcap_sniffer.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef pcap_sniffer_h
#define pcap_sniffer_h

#include <stdio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <pcap.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <sys/select.h>
#include "util.h"
#include "conn.h"
#include "dtrace.h"

// use apple libpcap header, uses private interface and has no
// kernel filtering (we get every pkt), but big plus is that it provides
// PID and process name associated with each pkt. so no need for
// dtrace, nstat, proc_pidinfo etc - fast and simple.
#define USE_PKTAP 1

#ifdef USE_PKTAP
// declarations of apple private libpcap functions,
// taken from https://opensource.apple.com/tarballs/libpcap/libpcap-67.tar.gz
int pcap_set_want_pktap(pcap_t *, int);
int pcap_set_filter_info(pcap_t *, const char *, int, bpf_u_int32);

// and header format,
// taken from www.opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/net/pktap.h
#define PKTAP_IFXNAMESIZE (IF_NAMESIZE + 8)
struct pktap_header {
	uint32_t	pth_length;				/* length of this header */
	uint32_t	pth_type_next;			/* type of data following */
	uint32_t	pth_dlt;				/* DLT of packet */
	char		pth_ifname[PKTAP_IFXNAMESIZE];	/* interface name */
	uint32_t	pth_flags;				/* flags */
	uint32_t	pth_protocol_family;
	uint32_t	pth_frame_pre_length;
	uint32_t	pth_frame_post_length;
	pid_t		pth_pid;				/* process ID */
	char		pth_comm[MAXCOMLEN+1];	/* process command name */
	uint32_t	pth_svc;				/* service class */
	uint16_t	pth_iftype;
	uint16_t	pth_ifunit;
	pid_t		pth_epid;		/* effective process ID */
	char		pth_ecomm[MAXCOMLEN+1];	/* effective command name */
};
#endif

#define PCAP_PORT 3
#define MAX_INTS 5 // max number of interfaces to monitor
#define MAX_MACS 10 // max number of MAC addresses 
#define STR_SIZE 1024
#define SNIFFER_LOOP_TIMEOUT 1 // 1 sec
#define SNAPLEN 512 // needs to be big enough to capture dns payload and allow for PKTAP header (which is around 150B)

typedef struct interface_t {
	char name[STR_SIZE];
	int num_addr;
	struct sockaddr_storage addr[MAX_INTS];
	uint8_t eth[ETHER_ADDR_LEN];
} interface_t;

typedef struct sniffer_t {
	pcap_t *pd;  // pcap listener
	interface_t intf; // interface to which listener is bound
	int fd;	// pcap fd used with select()
	int datalink; // datalink type
	int offset; // pcap header size
} sniffer_t;

typedef struct sniffers_t {
	int num_pds;
	sniffer_t sn[MAX_INTS];
	int use_pktap; // using apple PKTAP header with pcap
} sniffers_t;

typedef struct sniffer_callback_args_t {
	sniffers_t *sn;
	int i;
} sniffer_callback_args_t;

int refresh_sniffers_list(sniffers_t *sn, char* filter_exp, int quiet);
int setup_pd(interface_t *intf, pcap_t **pd, char* filter_exp, int use_pktap);
int get_interfaces(interface_t intf[MAX_INTS], int use_pktap);
char* find_intf(conn_raw_t* c, char* str, int len, uint8_t eth[ETHER_ADDR_LEN]);

void sniffer_loop(pcap_handler callback, int *running, char* tag, char* filter_exp, sniffers_t *sn, int use_pktap);
void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt);
void *listener(void *ptr);
void start_listener(void);
void close_sniffer_sock(void);
int get_DLT_offset2(int datalink);

#endif /* pcap_sniffer_h */
