// maintains list of active processes and their network connections

// proc_info interface documentation: https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/sys/proc_info.h.auto.html

#include "pid_conn_info.h"

//global
#define MAX_CONNS 1024
static conn_t conns[MAX_CONNS]={{0}};  // zero out array
static int num_conns=0;
static int last_pid=-1; // cache last PID looked up, to try to speed up find_conn()

//--------------------------------------------------------
//private

inline int is_ipv4_localhost(struct in6_addr* addr){
	const uint32_t dst_addr=((struct in_addr*)addr)->s_addr;
	return (dst_addr==htonl(INADDR_LOOPBACK));
}

inline int is_ipv6_localhost(struct in6_addr* addr){
	// is in6addr_loopback in host or network byte order ?
	return memcmp(&addr->s6_addr,&in6addr_loopback.s6_addr,16)==0;
}

int get_pid_name(int pid, char* name) {
	// get process name etc associated with pid
		struct proc_bsdshortinfo proc;
    int st = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &proc, 				PROC_PIDT_SHORTBSDINFO_SIZE);
    if (st != PROC_PIDT_SHORTBSDINFO_SIZE) {
        WARN("Cannot get process info for PID %d, likely has died.\n",pid);
        return -1;
    }
    strcpy(name,proc.pbsi_comm);
    return 0;
}

//--------------------------------------------------------
// swift interface

int refresh_active_conns(int localhost) {
	// called by GUI to update list of active process and network connections
	// (held in conns global var).
	// returns 1 if set of active connections has changed, else 0
	int changed = 0;
	
	DEBUG2("refresh_active_conns()\n");
	
	// get list of current processes
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);

	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = bufsize / sizeof(pid_t);

	// now walk through them
	//num_conns = 0;
	int k=0,j;
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
			strcpy(c.name, name);
			struct in_sockinfo* sockinfo = &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
			c.af=socketInfo.psi.soi_family;
			memset(&c.src_addr,0,sizeof(struct in6_addr));
			memset(&c.dst_addr,0,sizeof(struct in6_addr));
			if (sockinfo->insi_vflag==INI_IPV4) { // IPv4
				memcpy(&c.src_addr, &sockinfo->insi_laddr.ina_46.i46a_addr4, sizeof(struct in_addr));
				memcpy(&c.dst_addr, &sockinfo->insi_faddr.ina_46.i46a_addr4, sizeof(struct in_addr));
				if (!localhost && is_ipv4_localhost(&c.dst_addr))
					continue; // ignore localhost .
			} else { // IPv6
				memcpy(&c.src_addr, &sockinfo->insi_laddr.ina_6, sizeof(struct in6_addr));
				memcpy(&c.dst_addr, &sockinfo->insi_faddr.ina_6, sizeof(struct in6_addr));
				if (!localhost && is_ipv6_localhost(&c.dst_addr))
					continue; // ignore localhost .
			}
			inet_ntop(c.af, &c.src_addr, c.src_name, INET6_ADDRSTRLEN);
			inet_ntop(c.af, &c.dst_addr, c.dst_name, INET6_ADDRSTRLEN);
			// ignore IPv6 link-local connections
			char* mask="fe80:"; 
			if (strncmp(mask, c.src_name, strlen(mask)) == 0) {
				continue; // ignore IPv6 link local addresses
			}
			mask="0.0.0.0";
			if (strncmp(mask, c.src_name, strlen(mask)) == 0) {
				continue; // ignore IPV4 link local addresses
			}
			c.sport =  (int)ntohs(sockinfo->insi_lport);
			c.dport = (int)ntohs(sockinfo->insi_fport);
			
			char *state_str="(ESTABLISHED)";
			if (socketInfo.psi.soi_kind == SOCKINFO_IN) {
				if (c.dport != 443) continue; // we only log UDP to port 443 just now
				state_str="(UDP/QUIC)";
			}
	
			DEBUG2("%s(%d): %s:%d -> %s:%d %s\n", c.name, c.pid, c.src_name, c.sport, c.dst_name, c.dport, state_str);

			char* dns=lookup_dns_name(c.af,c.dst_addr);
			char dns2[BUFSIZE]={0};
			if (dns!=NULL) {
				sprintf(dns2," (%s)",dns);
			}

			strcpy(c.domain,dns2);
			sprintf(c.pid_name,"%s(%d)",c.name,c.pid);
			sprintf(c.conn_name,"%s:%d -> %s%s:%d %s",
								c.src_name,c.sport,
								c.dst_name, dns2, c.dport, state_str);
			sprintf(c.addr_name,"%s%s",c.dst_name, dns2);
			if (k < num_conns) {
				if (memcmp(&conns[k],&c,sizeof(conns[k]))==0) {
					// no change to this entry
					k++;
					continue;
				}
			}
			memcpy(&conns[k],&c,sizeof(c));
			changed = 1; // record fact that connections list has changed
			k++;
			if (k >= MAX_CONNS) {
				WARN("More than %d open network connections\n", MAX_CONNS);
				num_conns=MAX_CONNS;
				return changed;
			}
		}
	}
	num_conns=k;
	return changed;
}

conn_info_t get_conns(int row) {
	conn_info_t res;
	memset(&res,0,sizeof(res));
	res.pid = conns[row].pid;
	res.af = conns[row].af;
	res.addr = conns[row].dst_addr;
	strcpy(res.name,conns[row].name);
	strcpy(res.pid_name,conns[row].pid_name);
	strcpy(res.addr_name,conns[row].addr_name);
	strcpy(res.conn_name,conns[row].conn_name);
	strcpy(res.domain,conns[row].domain);
	return res;
}

int get_num_conns() {
	return num_conns;
}

//--------------------------------------------------------
// sniffer_blocker helpers

int find_pid_conn(conn_raw_t *c, char* name, int pid, int udp) {
	// get network connections associated with process pid and look for match with conn c
	
	// Figure out the size of the buffer needed to hold the list of open FDs
	int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (bufferSize == -1) {
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return -1;
	}
	// Get the list of open FDs
	struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
	if (!procFDInfo) {
		ERR("Out of memory. Unable to allocate buffer with %d bytes\n", bufferSize);
		return -1;
	}
	
	if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return -1;
	}
	int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
	
	int i;
	conn_t ci;
	for(i = 0; i < numberOfProcFDs; i++) {
		if (procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET)
			continue; // not a socket fd
		
		struct socket_fdinfo socketInfo;
		proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
		if(!udp && (socketInfo.psi.soi_kind != SOCKINFO_TCP))
			continue; // not a TCP socket
		if(udp && (socketInfo.psi.soi_kind == SOCKINFO_TCP))
			continue; // not a UDP socket

		struct in_sockinfo* sockinfo = &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
		ci.af=socketInfo.psi.soi_family;
		ci.sport =  (int)ntohs(sockinfo->insi_lport);
		ci.dport = (int)ntohs(sockinfo->insi_fport);
		if ( ( (c->dport != ci.dport) && (c->dport !=ci.sport) )
				|| ( (c->sport != ci.dport) && (c->sport !=ci.sport) )
				|| (c->af != ci.af) ) {
			continue; // not a match
		}
		
		if (sockinfo->insi_vflag==INI_IPV4) { // IPv4
			memcpy(&ci.src_addr, &sockinfo->insi_laddr.ina_46.i46a_addr4, sizeof(struct in_addr));
			memcpy(&ci.dst_addr, &sockinfo->insi_faddr.ina_46.i46a_addr4, sizeof(struct in_addr));
		} else { // IPv6
			memcpy(&ci.src_addr, &sockinfo->insi_laddr.ina_6, sizeof(struct in6_addr));
			memcpy(&ci.dst_addr, &sockinfo->insi_faddr.ina_6, sizeof(struct in6_addr));
		}
		
		if ( (are_addr_same(c->af,&c->dst_addr,&ci.dst_addr)) ||
				(are_addr_same(c->af,&c->src_addr,&ci.dst_addr)) )  {
			return 1;  // found match !
		}
	}
	return -1;
}

int find_conn(conn_raw_t *c, char* name, int *pid_hint, int udp) {
	// search list of active process and network connections for conn c
	// -- a streamlined (hopefully faster) version of refresh_active_conns() for use
	// in packet sniffing fast path
	// pid_hint is a guess as to the right pid, we check this first.  its just the pid of the
	// last connection found, but this already works pretty well.
		
	if (find_pid_conn(c, name, *pid_hint, udp)==1) {
		if (get_pid_name(*pid_hint, name)<0) return -1;
		return 1; // found it first time !
	}

	// fall back to walking list of all active processes ...
	// get list of current processes
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = bufsize / sizeof(pid_t);
	int j;
	for (j=0; j< num_pids; j++) {
		// get app name associated with process
		if (get_pid_name(pids[j], name)<0) continue; // process has died
		if (find_pid_conn(c, name, pids[j], udp)==1) {
			*pid_hint = pids[j]; // remember the PID
			return 1; // matched
		}
	}
	return 0;
}

inline int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2) {
	if (af==AF_INET) { // IPv4
		uint32_t _addr1 = ((struct in_addr*)addr1)->s_addr;
		uint32_t _addr2 = ((struct in_addr*)addr2)->s_addr;
		return (_addr1==_addr2);
	} else { // IPv6
		return (memcmp(&addr1->s6_addr, &addr2->s6_addr, 16)==0);
	}
}

int _find_pid_name(conn_raw_t *c) {
	// find name of process associated with a network connection tuple by walking list
	// of cached connections
	int i;
	for (i=0; i<num_conns; i++) {
		//printf("%d/%d %d/%d\n",sport,conns[i].sport,dport,conns[i].dport);
		if ((c->dport != conns[i].dport) && (c->dport !=conns[i].sport) ) continue;
		if ((c->sport != conns[i].dport) && (c->sport !=conns[i].sport) ) continue;
		if (c->af!=conns[i].af) continue;
		//printf("%s %s\n",conns[i].conn_name,inet_ntoa(dst_addr));
		if (are_addr_same(c->af,&c->dst_addr,&conns[i].dst_addr)) {
			return i;
		}
	}
	return -1;
}

int find_pid(conn_raw_t *c, char*name, int udp){
	// find name of process associated with a network connection tuple
	// (assumed to be an outgoing tuple, so src is local addr and dst is remote)

	// start by trying cached list of connections, v fast if we get match
	int res = _find_pid_name(c);
	if (res>=0) {
		last_pid = conns[res].pid;
		strcpy(name,conns[res].name);
		return 1;
	}

	// didn't find PID, usual with new connections (SYN-ACK).  make syscall to query current
	// list of actice questions, can be slow so we try to help speed things up by
	// caching last PID and using a streamlined search routine find_conn()
	char dn[INET6_ADDRSTRLEN];
	inet_ntop(c->af, &c->dst_addr, dn, INET6_ADDRSTRLEN);
	res = find_conn(c,name, &last_pid, udp);
	if (res==1) {
		DEBUG2("find_pid() retrying for %s ... found\n", dn);
		return 1;
	}
	// couldn't find PID.  likely was an emphemeral process that opening a brief connection and has gone away
	// by time we get here (a few ms typically, and never more than 10ms).
	INFO("find_pid() retrying for %s ... not found\n", dn);
	return 0;
}




