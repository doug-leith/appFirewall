//
//  tests.m
//  appFirewallTests
//
//  Created by Doug Leith on 03/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface tests : XCTestCase

@end

#include "../util.h"
#include "../pcap_sniffer.h"

@implementation tests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testUtils {
	char test[1024]; strcpy(test,"  123 4 ");
	XCTAssertEqual(strcmp(trimwhitespace(test),"123 4"),0);
	int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);
	
	struct in6_addr a;
	memset(&a,1,sizeof(a)); 
	struct in6_addr a2;
	memcpy(&a2,&a,sizeof(a2));
	XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),1);
	XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),1);
	memset(&a2,0,sizeof(a2));
	XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),0);
	XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),0);

	int pid=-1;
	FILE* fp = run_cmd_pipe("/bin/ps", "-p1", &pid);
	XCTAssertNotEqual(fp,NULL);
	XCTAssertGreaterThanOrEqual(pid,1);
	char resp[STR_SIZE];
	int res = readline_timed(resp,STR_SIZE,fp,1);
	XCTAssertGreaterThanOrEqual(res,0);
	XCTAssertGreaterThan(strlen(resp),0);
	//printf("%s\n",resp);
	XCTAssertEqual(strcmp(resp,"  PID TTY           TIME CMD"),0);
	fclose(fp);
	XCTAssertEqual(readline_timed(resp,STR_SIZE,fp,1),-1);
	fp = fopen("/dev/null","r");
	XCTAssertEqual(readline_timed(resp,STR_SIZE,fp,1),0);
	fclose(fp);
	
	fp = run_cmd_pipe("/bin/ps", "-p1", &pid);
	int fd = fileno(fp);
	char inbuf[LINEBUF_SIZE], line[LINEBUF_SIZE]; size_t inbuf_used=0;
	res = read_line(fd, inbuf, &inbuf_used, line);
	XCTAssertEqual(res,29);
	XCTAssertGreaterThan(inbuf_used,30);
	printf("1: %d/%zu,%s\n",res,inbuf_used,line);
	XCTAssertEqual(strcmp(line,"  PID TTY           TIME CMD\n"),0);
	res = read_line(fd, inbuf, &inbuf_used, line);
	printf("2: %d/%zu,%s\n",res,inbuf_used,line);
	XCTAssertGreaterThan(res,30);
	XCTAssertEqual(inbuf_used,0);
	XCTAssertNotEqual(strstr(line,"/sbin/launchd\n"),NULL);
	fclose(fp);
		
	XCTAssertEqual(run_cmd("ps -p 1",1),1);
	XCTAssertEqual(run_cmd("whereis nothing",1),0);
}

// need to add a bunch of stubs to allow decent testing of the rest
- (void)testPcapSniffer {
	struct sockaddr_in gw;
	XCTAssertEqual(get_default_gateway(AF_INET, (struct sockaddr *)&gw),1);

	uint8_t eth[ETHER_ADDR_LEN];
	XCTAssertNotEqual(get_default_gateway_eth(AF_INET, eth),NULL);
	
	char name[1024];
	XCTAssertNotEqual(get_intf_name("en0", 0, name),NULL);
	XCTAssertEqual(strcmp(name,"en0"),0);
	XCTAssertNotEqual(get_intf_name("en0", 1, name),NULL);
	XCTAssertEqual(strcmp(name,"iptap,lo0,en0"),0);
	
	interface_t intf[MAX_INTS];
	XCTAssertGreaterThan(get_interfaces(intf, 0),0);
	printf("%s\n",intf[0].name);
	XCTAssertEqual(strcmp(intf[0].name,"en0"),0);
	
	conn_raw_t c;
	c.af=AF_INET;
	memcpy(&c.src_addr, &((struct sockaddr_in*)&intf[0].addr)->sin_addr, 4);
	XCTAssertNotEqual(find_intf(&c, intf),NULL);
	XCTAssertEqual(strcmp(intf[0].name,"en0"),0);
	
	XCTAssertEqual(get_DLT_offset2(DLT_EN10MB),14);
	XCTAssertEqual(get_DLT_offset2(DLT_RAW),0);
	
	// to do: add stubs for testing. just now need to be root to check:
	// int setup_pd(interface_t* intf, pcap_t **pd, char* filter_exp, int use_pktap)
	//int refresh_sniffers_list(sniffers_t *sn, char* filter_exp, int quiet)
	//void sniffer_callback(u_char* raw_args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) calls snd_rst()
	// void sniffer_loop(pcap_handler callback, int *running, char* tag, char* filter_exp, sniffers_t *sn, int use_pktap) 
}

- (void)testSndRST {
	// need to be root to check:
	// void init_libnet(libnet_data_t *ld)
	// etc
	// replace sock_raw call within libnet with stub ?
}

- (void)testCatchEscapee {
	// to do: add stubs to test find_fds() and catcher_callback()
	//int find_fds(int pid, int af, struct in6_addr dst, uint16_t sport, uint16_t dport, conn_raw_t *cr)
	// void catcher_callback(u_char* raw_args, const struct pcap_pkthdr *pkthdr, const u_char* pkt) calls snd_rst
	//void *catcher_listener(void *ptr) uses network
}

- (void)testCmd {
	// need to be root to run dnscrypt
	// void* dnscrypt(void* ptr)
	// int set_dns_server(char* dns)
	// void* cmd_accept_loop(void* ptr) uses network and most cmds need root
}

- (void)testCodesign {
	// these tests need appFirewall and TextEdit installed in /Applications
	XCTAssertEqual(check_file_signature("/Applications/appFirewall.app/Contents/Library/dnscrypt-proxy",1),1);
	XCTAssertEqual(check_file_signature("/Applications/TextEdit.app",1),-1);
}

@end
