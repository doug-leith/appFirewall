// maintains list of active processes and their network connections

// proc_info interface documentation: https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/sys/proc_info.h.auto.html

#include "pid_conn_info.h"

//global
list_t pid_list=LIST_INITIALISER;
#define STR_SIZE 1024

//--------------------------------------------------------
//private

inline int is_ipv4_localhost(struct in6_addr* addr){
	const uint32_t dst_addr=((struct in_addr*)addr)->s_addr;
	return (dst_addr==htonl(INADDR_LOOPBACK))
					|| (dst_addr==htonl(INADDR_ANY));
}

inline int is_ipv6_localhost(struct in6_addr* addr){
	// is in6addr_loopback in host or network byte order ?
	return memcmp(&addr->s6_addr,&in6addr_loopback.s6_addr,16)==0;
}

int get_pid_name(int pid, char* name) {
	// get process name etc associated with pid
		struct proc_bsdshortinfo proc;
    int st = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &proc, 				PROC_PIDT_SHORTBSDINFO_SIZE);
    if (st != PROC_PIDT_SHORTBSDINFO_SIZE) {
				INFO("Cannot get process info for PID %d, likely has died.\n",pid);
        return -1;
    }
    strlcpy(name,proc.pbsi_comm,MAXCOMLEN);
    return 0;
}

char* pid_hash(const void *it) {
	// generate table lookup key string
	// we do this by network connection, so child processes that
	// share the same fd are lumped together
	conn_t *item = (conn_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	inet_ntop(item->raw.af,&item->raw.src_addr,sn,INET6_ADDRSTRLEN);
	inet_ntop(item->raw.af,&item->raw.dst_addr,dn,INET6_ADDRSTRLEN);
	char* temp = malloc(2*INET6_ADDRSTRLEN+64);
	sprintf(temp,"%s:%d-%s:%d",sn,item->raw.sport,dn,item->raw.dport);
	return temp;
}

int pid_cmp(const void* it1, const void* it2){
	conn_t *item1 = (conn_t*) it1;
	conn_t *item2 = (conn_t*) it2;
	char * temp1 = pid_hash(item1);
	char * temp2 = pid_hash(item2);
	int res = (strcmp(temp1,temp2)==0);
	free(temp1); free(temp2);
	return res;
}

//--------------------------------------------------------
// swift interface

void init_pid_list() {
	init_list(&pid_list,pid_hash,pid_cmp,0);
}

int refresh_active_conns(int localhost) {
	// called by GUI to update list of active process
	// and network connectionsb(held in conns global var).
	// returns 1 if set of active connections has changed,
	// else 0, so that GUI knows whether it has to redraw itself
	int changed = 0;
	
	DEBUG2("refresh_active_conns()\n");
		
	list_t prev_list=pid_list;
	init_list(&pid_list,pid_hash,pid_cmp,0);
	
	// get list of current processes
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);

	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = bufsize / sizeof(pid_t);

	// now walk through them
	//num_conns = 0;
	int j;
	for (j=0; j< num_pids; j++) {
		int pid = pids[j];
		
		// get app name associated with process
		char name[MAXCOMLEN];
		if (get_pid_name(pid, name)<0) {
			// problem getting name for PID, probably process has stopped
			// between call to proc_listpids() above and our call to get_pid_name()
			continue;
		}
		
		// get network connections associated with process
		// Figure out the size of the buffer needed to hold the list of open FDs
		int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
		if (bufferSize == -1) {
			// probably process has stopped
			WARN("Unable to get open file handles for PID %d\n", pid);
			continue;
		}
		// Get the list of open FDs
		struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
		if (!procFDInfo) {
			ERR("Out of memory. Unable to allocate buffer with %d bytes\n", bufferSize);
			return 0;
		}

		if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
			// probably process has stopped
			WARN("Unable to get open file handles for PID %d\n", pid);
			continue;
		}
		int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
		
		int i;
		for(i = 0; i < numberOfProcFDs; i++) {
			conn_t c; // the new connection
			memset(&c,0,sizeof(c));
			
			if (procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET)
				continue; // not a socket fd
			struct socket_fdinfo socketInfo;
			proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);

			int state = socketInfo.psi.soi_proto.pri_tcp.tcpsi_state;
			if ((socketInfo.psi.soi_kind != SOCKINFO_TCP)
				&& (socketInfo.psi.soi_kind != SOCKINFO_IN)) continue; // unix sock or the like
			if ((socketInfo.psi.soi_kind == SOCKINFO_TCP) && (state != TSI_S_ESTABLISHED))
				continue; // TCP, but not an established connection. don't log it

			c.pid=pid;
			strlcpy(c.name, name, MAXCOMLEN);
			struct in_sockinfo* sockinfo = &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
			c.raw.af=socketInfo.psi.soi_family;
			memset(&c.raw.src_addr,0,sizeof(struct in6_addr));
			memset(&c.raw.dst_addr,0,sizeof(struct in6_addr));
			if (sockinfo->insi_vflag==INI_IPV4) { // IPv4
				memcpy(&c.raw.src_addr, &sockinfo->insi_laddr.ina_46.i46a_addr4, sizeof(struct in_addr));
				memcpy(&c.raw.dst_addr, &sockinfo->insi_faddr.ina_46.i46a_addr4, sizeof(struct in_addr));
				if (!localhost && is_ipv4_localhost(&c.raw.dst_addr))
					continue; // ignore localhost .
			} else { // IPv6
				memcpy(&c.raw.src_addr, &sockinfo->insi_laddr.ina_6, sizeof(struct in6_addr));
				memcpy(&c.raw.dst_addr, &sockinfo->insi_faddr.ina_6, sizeof(struct in6_addr));
				if (!localhost && is_ipv6_localhost(&c.raw.dst_addr))
					continue; // ignore localhost .
			}
			inet_ntop(c.raw.af, &c.raw.src_addr, c.src_addr_name, INET6_ADDRSTRLEN);
			inet_ntop(c.raw.af, &c.raw.dst_addr, c.dst_addr_name, INET6_ADDRSTRLEN);
			// ignore IPv6 link-local connections
			char* mask="fe80:"; 
			if (strncmp(mask, c.src_addr_name, strlen(mask)) == 0) {
				continue; // ignore IPv6 link local addresses
			}
			c.raw.sport =  (int)ntohs(sockinfo->insi_lport);
			c.raw.dport = (int)ntohs(sockinfo->insi_fport);
			
			// we only log UDP to port 443 just now (likely QUIC)
			c.raw.udp = (socketInfo.psi.soi_kind == SOCKINFO_IN)
									&& (c.raw.dport == 443);
	
			DEBUG2("%s(%d): %s:%d -> %s:%d %d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.dst_addr_name, c.raw.dport, c.raw.udp);

			char* dns=lookup_dns_name(c.raw.af,c.raw.dst_addr);
			if (dns!=NULL) {
				strlcpy(c.domain,dns,BUFSIZE);
			} else {
				strlcpy(c.domain,c.dst_addr_name,INET6_ADDRSTRLEN);
			}
			// ignore child processes sharing conn of parent
			// - rely here on fact that parent will be processed
			// here before any child ...
			if (in_list(&pid_list, &c, 0)) continue;
			// flag to GUI if it needs to refresh ..
			if (!in_list(&prev_list, &c, 0)) changed = 1;
			add_item(&pid_list,&c,sizeof(conn_t));
		}
	}
	free_list(&prev_list);
	return changed;
}

conn_t* get_conns(int row) {
	return get_list_item(&pid_list,row);
}

int get_num_conns() {
	return get_list_size(&pid_list);
}

//--------------------------------------------------------
// sniffer_blocker helpers

int find_pid(conn_raw_t *cr, char*name){
	// find name of process associated with a network connection tuple
	// (assumed to be an outgoing tuple, so src is local addr and dst
	// is remote)

	// start by trying cached list of connections, v fast if we get match
	conn_t c;
	memcpy(&c.raw,cr,sizeof(conn_raw_t));
	conn_t *res = in_list(&pid_list,&c,0); // list lookup only uses raw
	if (res) { // found it !
		strlcpy(name,res->name,BUFSIZE);
		return 1;
	}

	// didn't find PID, usual with new connections (SYN-ACK).  make syscall
	// to query current list of active questions, can be slow
	char dn[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
	refresh_active_conns(0);
	res = in_list(&pid_list,&c,0);
	if (res) { // found it !
		strlcpy(name,res->name,BUFSIZE);
		return 1;
	}
	// couldn't find PID.  likely was an emphemeral process that opening a
	// brief connection and has gone away by time we get here (a few ms typically, and never more than 10ms).
	INFO("find_pid() retrying for %s ... not found\n", dn);
	return 0;
}




