//
//  netstats.c
//  appFirewall
//
//  Created by Doug Leith on 04/01/2020.
//
// 	Based on: Jonathan Levin, http://NewOSXBook.com/
//  http://newosxbook.com/src.jl?tree=listings&file=netbottom.c

#include "netstats.h"

static list_t nstat_cache;
static dispatch_queue_t nstat_q;

int lookup_nstat(conn_raw_t *cr, char* name, int* pid) {
	// get PID name corresponding to connection cr
	conn_t c;
	c.raw = *cr;
	//inet_ntop(c.raw.af,&c.raw.src_addr,c.src_addr_name,INET6_ADDRSTRLEN);
	//inet_ntop(c.raw.af,&c.raw.dst_addr,c.dst_addr_name,INET6_ADDRSTRLEN);
	conn_t *res = in_list(&nstat_cache, &c, 0);
	if (res != NULL) {
		strlcpy(name,res->name,MAXCOMLEN);
		*pid = res->pid;
		return 1;
	}
	return 0;
}

void (^description_callback_block) (CFDictionaryRef) = ^(CFDictionaryRef Desc) {

	// Called when another API asks for a source description, which this
	// sample does on source addition..

	conn_t c; memset(&c,0,sizeof(c));
	
	// process name
	CFStringRef pName = CFDictionaryGetValue(Desc, kNStatSrcKeyProcessName);
	CFStringGetCString(pName, c.name, MAXCOMLEN, kCFStringEncodingUTF8);

	// process PID
	CFNumberRef pIdentifier = CFDictionaryGetValue(Desc, kNStatSrcKeyPID);
	CFNumberGetValue (pIdentifier, kCFNumberSInt32Type, &c.pid);
	
	// get remote address
	CFDataRef addr =  (CFDictionaryGetValue(Desc, kNStatSrcKeyRemote));
	CFIndex len = CFDataGetLength(addr);
	struct sockaddr *remoteSA = alloca (len);  // enough
	CFDataGetBytes(addr, // CFDataRef theData,
			CFRangeMake(0,len), // CFRange range,
			(UInt8 *)remoteSA); //UInt8 *buffer);

	// get local address
	addr =  (CFDictionaryGetValue(Desc, kNStatSrcKeyLocal));
	len = CFDataGetLength(addr);
	struct sockaddr *localSA = alloca (len);  // enough
	CFDataGetBytes(addr, // CFDataRef theData,
			CFRangeMake(0,len), // CFRange range,
			(UInt8*)localSA); //UInt8 *buffer);

	c.raw.af = remoteSA->sa_family;

	if (c.raw.af == AF_INET) {
		// if its a broadcast, ignore
		if ( ((struct sockaddr_in *)localSA)->sin_addr.s_addr == INADDR_ANY) return;
		memcpy(&c.raw.src_addr,&((struct sockaddr_in *)localSA)->sin_addr, sizeof(struct in_addr));
		memcpy(&c.raw.dst_addr,&((struct sockaddr_in *)remoteSA)->sin_addr, sizeof(struct in_addr));
		c.raw.sport = ntohs(((struct sockaddr_in *)localSA)->sin_port);
		c.raw.dport = ntohs(((struct sockaddr_in *)remoteSA)->sin_port);

	} else {
		memcpy(&c.raw.src_addr,&((struct sockaddr_in6 *)localSA)->sin6_addr, sizeof(struct in6_addr));
		memcpy(&c.raw.dst_addr,&((struct sockaddr_in6 *)remoteSA)->sin6_addr, sizeof(struct in6_addr));
		c.raw.sport = ntohs(((struct sockaddr_in6 *)localSA)->sin6_port);
		c.raw.dport = ntohs(((struct sockaddr_in6 *)remoteSA)->sin6_port);
	}

	DEBUG2("nstat: %s %s\n", c.name, conn_hash(&c));
	add_item(&nstat_cache,&c,sizeof(conn_t));
};

void (^callback_block) (void *, void *)  = ^(NStatSourceRef Src, void *arg2){
 // Arg is NWS[TCP/UDP]Source
 NStatSourceSetDescriptionBlock (Src, description_callback_block);
 (void) NStatSourceQueryDescription(Src);
};

void start_netstats() {
	init_list(&nstat_cache,conn_hash,NULL,1,-1,"nstat_cache");
	nstat_q = dispatch_queue_create("com.leith.appFirewall.nstat_q", NULL);
	NStatManagerRef 	nm = NStatManagerCreate (kCFAllocatorDefault,
																						 //&_dispatch_main_q,
																						 nstat_q,
																						 callback_block);
	NStatManagerSetFlags(nm, 0);

	// This is a really cool undocumented feature of NetworkStatistics.framework
	// Which will give you the actual control socket data output.
	int fd = open ("/tmp/nettop.trace", O_RDWR| O_CREAT | O_TRUNC, 0644);
	NStatManagerSetInterfaceTraceFD(nm, fd);

	//if (wantUDP) { rc = NStatManagerAddAllUDPWithFilter (nm, 0 , 0);}
	NStatManagerAddAllTCPWithFilter (nm, 0 , 0);
}
