//
//  pid_conn_info_test.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "pid_conn_info.h"
#include "conn_list.h"

@interface pid_conn_info_test : XCTestCase

@end

// stubs
char* stub_pid_name="test"; // fake pid name to return from call to proc_pidinfo()
int stub_ret_val = -1;
int stub_fdtype=PROX_FDTYPE_SOCKET;
int stub_fd=1;
int proc_pidinfo_stub(int pid, int flavor, uint64_t arg, void *buffer, int buffersize){
	struct proc_bsdshortinfo *p;
	struct proc_fdinfo *fd;
	switch (flavor) {
	case PROC_PIDLISTFDS:
		if (buffer == NULL) return stub_ret_val;
		fd = (struct proc_fdinfo *)buffer;
		fd->proc_fdtype = stub_fdtype;
		fd->proc_fd = stub_fd;
		return 0;
	case PROC_PIDT_SHORTBSDINFO:
		p = (struct proc_bsdshortinfo *)buffer;
		p->pbsi_status = 2;
		strlcpy(p->pbsi_comm,stub_pid_name,MAXCOMLEN);
		return stub_ret_val;
	}
	return 0;
}
int stub_soi_kind = SOCKINFO_TCP;
int tcpsi_state = TSI_S_ESTABLISHED;
char* stub_src_addr = "8.8.8.8", *stub_dst_addr="9.9.9.9";
uint16_t stub_sport=1, stub_dport=2;
int proc_pidfdinfo_stub(int pid, int fd, int flavor, void * buffer, int buffersize){
	struct socket_fdinfo *s;
	switch (flavor) {
	case PROC_PIDFDSOCKETINFO:
		s = (struct socket_fdinfo*)buffer;
		s->psi.soi_kind = stub_soi_kind; //SOCKINFO_IN
		s->psi.soi_proto.pri_tcp.tcpsi_state = tcpsi_state;
		s->psi.soi_family=AF_INET;
		s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag=INI_IPV4;
		inet_pton(AF_INET,stub_src_addr, &s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4);
		inet_pton(AF_INET,stub_dst_addr, &s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4);
		s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = htons(stub_sport);
		s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = htons(stub_dport);
		return sizeof(struct socket_fdinfo);
	}
	return 0;
}
int listpids_ret_val = sizeof(pid_t);
int listpids_pid = 100;
int proc_listpids_stub(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize){
	if (buffer == NULL) return listpids_ret_val;
	pid_t* p;
	p = (pid_t*)buffer;
	p[0] = listpids_pid;
	return sizeof(pid_t);
}
conn_t *e_stub=NULL;
int called_stub = 0;
void start_catch_escapee_stub(conn_t *e){
	called_stub = 1;
	e_stub = e;
}
int is_ppp_val = 0;
int is_ppp_stub(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr){
	return is_ppp_val;
}

@implementation pid_conn_info_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}
- (void)testPidInfo {
	// replace syscalls with stubs
	pid_info_t *pid_info = get_pid_info();
	pid_info->proc_pidinfo = &proc_pidinfo_stub;
	pid_info->proc_pidfdinfo = &proc_pidfdinfo_stub;
	pid_info->proc_listpids= &proc_listpids_stub;
	
	// name lookup
	char name[MAXCOMLEN]; uint32_t status;
	int pid = 1;
	stub_ret_val = PROC_PIDT_SHORTBSDINFO_SIZE;
	XCTAssertEqual(get_pid_name(pid, name, NULL),0);
	XCTAssertEqual(strcmp(name,"test"),0);
	XCTAssertEqual(get_pid_name(pid, name, &status),0);
	XCTAssertEqual(status,2);
		
	init_pid_lists();
	conn_raw_t cr; memset(&cr,1,sizeof(cr)); cr.af=AF_INET;
	conn_t c; c.raw = cr;
	c.pid = 10; c.fd=23; strcpy(c.name,"test2");
	add_item(&pid_info->pid_list,&c,sizeof(c));
	
	// conn lookup
	conn_t *res = find_conn(c.pid, c.fd);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(memcmp(&res->raw,&cr,sizeof(cr)),0);
	XCTAssertEqual(find_conn(0, 0),NULL); // not in list
	
	// main call to proc_pidfdinfo
	pid_info->changed = 0;
	// test error cases
	clear_list(&pid_info->pid_list);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),0);
	stub_ret_val = -1;
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),0);
	stub_ret_val = PROC_PIDLISTFD_SIZE;
	stub_fdtype=PROX_FDTYPE_SOCKET+1; // not a socket
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),0);
	stub_fdtype=PROX_FDTYPE_SOCKET;
	stub_soi_kind = -1; // not tcp or udp
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),0);
	stub_soi_kind = SOCKINFO_TCP;
	tcpsi_state = -1; // tcp but not established
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),0);
	XCTAssertEqual(pid_info->changed,0);
	
	// tcp and established
	printf("tcp and established\n");
	tcpsi_state = TSI_S_ESTABLISHED;
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),1);
	conn_t *resc = get_list_item(&pid_info->pid_list, 0);
	XCTAssertEqual(resc->raw.af,AF_INET);
	XCTAssertEqual(resc->fd,stub_fd);
	XCTAssertEqual(resc->raw.sport,stub_sport);
	XCTAssertEqual(resc->raw.dport,stub_dport);
	XCTAssertEqual(resc->raw.udp,0);
	XCTAssertEqual(strcmp(resc->src_addr_name,stub_src_addr),0);
	XCTAssertEqual(strcmp(resc->dst_addr_name,stub_dst_addr),0);
	XCTAssertEqual(strcmp(resc->domain,stub_dst_addr),0);
	XCTAssertEqual(strcmp(resc->name,c.name),0);
	XCTAssertEqual(resc->pid,c.pid);
	XCTAssertEqual(pid_info->changed,1);

	// localhost is ignored
	clear_list(&pid_info->pid_list); pid_info->changed = 0;
	stub_dst_addr="127.0.0.1";
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),0);
  XCTAssertEqual(pid_info->changed,0);
  
	// dns lookup
	stub_dst_addr="1.2.1.2";
	struct in6_addr a;
	inet_pton(AF_INET,stub_dst_addr,&a);
	load_dns_cache("empty"); // will clear cache
	append_dns(AF_INET, a, "test1.2.1.2");
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),1);
	resc = get_list_item(&pid_info->pid_list, 0);
	//printf("***test 1.1.1.2: %s\n",resc->domain);
	XCTAssertEqual(strcmp(resc->domain,"test1.2.1.2"),0);
	XCTAssertEqual(pid_info->changed,1);

	// duplicate
	pid_info->changed = 0;
	XCTAssertEqual(find_fds(c.pid, c.name, &pid_info->pid_list, 1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),1);
	XCTAssertEqual(pid_info->changed,0);
	
	//to do: check fd caching
	
	pid_info->changed = 0;
	XCTAssertEqual(get_pid_changed(),0);
	pid_info->changed = 1;
	XCTAssertEqual(get_pid_changed(),1);
	clear_pid_changed();
	XCTAssertEqual(get_pid_changed(),0);
	
	// streaming lookup with hit in pid_list
	clear_list(&pid_info->last_pid_list);
	clear_list(&pid_info->pid_list);
	add_item(&pid_info->pid_list,&c,sizeof(c));
	char name2[MAXCOMLEN];
	XCTAssertEqual(find_pid(&cr, name2, 0),1);
	XCTAssertEqual(strcmp(name2,"test2"),0);
	XCTAssertEqual(get_list_size(&pid_info->last_pid_list),1);
	// last call will have cached pid_cache, so try again
	clear_list(&pid_info->pid_list); // so will inspect cache
	XCTAssertEqual(find_pid(&cr, name2, 0),0); // pid not found
	// change conn to match stub
	cr.af = AF_INET;
	inet_pton(AF_INET,stub_src_addr, &cr.src_addr);
	inet_pton(AF_INET,stub_dst_addr, &cr.dst_addr);
	cr.sport = stub_sport; cr.dport = stub_dport;
	clear_list(&pid_info->pid_list); // so will inspect cache
	clear_list(&pid_info->last_pid_list);
	XCTAssertEqual(find_pid(&cr, name2, 0),0); // not in list, not in cache
	cache_pid(1,"test"); // cache entry will prompt call to procfdinfo
	XCTAssertEqual(find_pid(&cr, name2, 0),1); // finds it now
	XCTAssertEqual(strcmp(name2,"test"),0);

	//refresh_active_conns
	clear_list(&pid_info->pid_list);
	pid_info->changed = 0;
	stub_ret_val = PROC_PIDT_SHORTBSDINFO_SIZE;
	XCTAssertEqual(refresh_active_conns(1),1);
	XCTAssertEqual(get_list_size(&pid_info->pid_list),1);
	// call again, and shouldn't update since no change
	pid_info->changed = 0;
	XCTAssertEqual(get_num_gui_conns(),0);
	update_gui_pid_list(); // copy pid_list over to gui
	XCTAssertEqual(get_num_gui_conns(),1);
	XCTAssertEqual(refresh_active_conns(1),0); // no change
	XCTAssertEqual(get_list_size(&pid_info->pid_list),1);
	XCTAssertEqual(get_list_size(&pid_info->gui_pid_list),1);

	// gui_pid_list
	// update with no change
	update_gui_pid_list(); // copy pid_list over to gui
	XCTAssertEqual(get_list_size(&pid_info->gui_pid_list),1);
	XCTAssertEqual(get_num_gui_conns(),1);
	conn_t resc2 = get_gui_conn(0);
	XCTAssertEqual(resc2.raw.af,AF_INET);
	XCTAssertEqual(resc2.fd,stub_fd);
	XCTAssertEqual(resc2.raw.sport,stub_sport);
	XCTAssertEqual(resc2.raw.dport,stub_dport);
	XCTAssertEqual(resc2.raw.udp,0);
	XCTAssertEqual(strcmp(resc2.src_addr_name,stub_src_addr),0);
	XCTAssertEqual(strcmp(resc2.dst_addr_name,stub_dst_addr),0);
	//printf("**resc2:%s\n",resc2.name);
	XCTAssertEqual(strcmp(resc2.name,"test"),0);
	
	// hard to test these since they involve creating threads:
	//void start_pid_watcher(void);
	//void signal_pid_watcher(int force, int full_refresh);
	//void set_pid_watcher_hook(void (*hook)(void));
}

- (void)testEscapees {
	pid_info_t *pid_info = get_pid_info();
	pid_info->start_catch_escapee = &start_catch_escapee_stub;
	pid_info->is_ppp = &is_ppp_stub;
	
	init_pid_lists();
	// called with empty pid list
	find_escapees();
	XCTAssertEqual(called_stub,0);

	// item on pid list, empty log. not blocked
	conn_raw_t cr; memset(&cr,1,sizeof(cr)); cr.af=AF_INET; cr.udp=0;
	conn_t c; c.raw = cr;
	c.pid = 10; c.fd=23; strcpy(c.name,"test");
	strcpy(c.domain,"testdomain");
	add_item(&pid_info->pid_list,&c,sizeof(c));
	set_path("/tmp/");
	load_log("empty", "txt_log");
	load_connlist(get_blocklist(),"empty");
	load_connlist(get_whitelist(),"empty");
	called_stub = 0; 	is_ppp_val=0;
	find_escapees();
	XCTAssertEqual(called_stub,0);

	// item is now on blacklist
	bl_item_t item;
	strcpy(item.name,"test"); strcpy(item.domain,"testdomain");strcpy(item.addr_name,"testaddr");
	add_connitem(get_blocklist(),&item);
	XCTAssertEqual(is_blocked(&item),1);
	load_log("empty", "txt_log");
	pid_info->escapee_thread_count = 0;
	called_stub = 0;
	//printf("***escapee\n");
	find_escapees();
	XCTAssertEqual(get_log_size(),1); // new log entry
	XCTAssertEqual(get_list_size(&pid_info->escapee_list),1); // new escapee list entry
	XCTAssertEqual(called_stub,1); // catcher called
	XCTAssertNotEqual(e_stub,NULL);
	XCTAssertEqual(e_stub->raw.af,cr.af);
	XCTAssertEqual(e_stub->raw.sport,cr.sport);
	XCTAssertEqual(e_stub->raw.dport,cr.dport);
	XCTAssertEqual(e_stub->raw.udp,cr.udp);
	XCTAssertEqual(memcmp(&e_stub->raw.src_addr,&cr.src_addr,sizeof(cr.src_addr)),0);
	XCTAssertEqual(memcmp(&e_stub->raw.dst_addr,&cr.src_addr,sizeof(cr.dst_addr)),0);

	// ignore vpn conns
	called_stub = 0;
	is_ppp_val=1; // vpn
	find_escapees();
	XCTAssertEqual(called_stub,0);

	//void *catch_escapee(void *ptr);

}

@end
