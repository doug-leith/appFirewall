// maintains list of active processes and their network connections

// proc_info interface documentation: https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/sys/proc_info.h.auto.html

#include "pid_conn_info.h"

//global
static list_t pid_list=LIST_INITIALISER;
static list_t gui_pid_list=LIST_INITIALISER; // filtered list for GUI
#define STR_SIZE 1024
static int changed = 0; // flag to GUI if pid list has changed

// thread globals
static pthread_cond_t pid_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t pid_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t pid_thread; // handle to pid watcher thread
static int pid_thread_started = 0; // indicates whether pid watcher thread already running
static int wakeup = 0;
static void (*pid_watcher_hook)(void) = NULL;

//--------------------------------------------------------
// swift interface

// thread safety for pid_list:
// -pid_watcher runs in its own thread and calls refresh_active_conns().
// -get_conn(),get_num_conns(),get_pid_changed(),set_pid_changed() are called from
// swift ActiveConnsViewController which runs in a separate thread
// -find_pid() is called by sniffer_blocker listener (via create_blockitem_from_addr())
// from its own thread, and also from pid_watcher_hook()

void *pid_watcher(void *ptr) {
	// runs in its own thread to keep pid_list uodated
	struct timespec ts;
	int res=0;
	refresh_active_conns(0); // takes lock itself as needed
	for(;;) {
		clock_gettime(CLOCK_REALTIME, &ts);
		# define PID_WATCHER_TIMEOUT 500 // in ms
		ts.tv_nsec += PID_WATCHER_TIMEOUT*1000*1000;
		
		pthread_mutex_lock(&pid_mutex);
		res = 0;
		// release mutex and wait (either for timeout or a signal from]
		// sniffer_blocker that a new conn has started) ...
		while ((wakeup==0) && (res != ETIMEDOUT)) {
			res = pthread_cond_timedwait(&pid_cond, &pid_mutex, &ts);
		}
		wakeup = 0; // if a signal occurs now this will be reset to be non-zero
		// have lock on mutex here.  release it
		pthread_mutex_unlock(&pid_mutex);
		
		refresh_active_conns(0); // will take lock as needed

		// handle waiting list, will take lock as needed
		if (pid_watcher_hook != NULL) pid_watcher_hook();
	}
}

void start_pid_watcher() {
	// fire up watcher thread
	if (pid_thread_started==0) {
		init_pid_list();
		pthread_create(&pid_thread, NULL, pid_watcher, NULL);
		pid_thread_started=1;
	}
}

void signal_pid_watcher() {
	// ask watcher to refresh pid_list
	pthread_mutex_lock(&pid_mutex);
	wakeup = 1;
	pthread_cond_signal(&pid_cond);
	pthread_mutex_unlock(&pid_mutex);
}

void set_pid_watcher_hook(void (*hook)(void)) {
	// callback in watched.  used by sniffer_blocker to update its waiting list
	pid_watcher_hook = hook;
}

conn_t* get_conn(int row) {
	// for use by swift GUI
	pthread_mutex_lock(&pid_mutex);
	if (row > get_list_size(&gui_pid_list)) {
		pthread_mutex_unlock(&pid_mutex);
		return NULL;
	}
	// take a copy of list item while we have lock
	conn_t * c = malloc(sizeof(conn_t));
	memcpy(c,get_list_item(&gui_pid_list,row),sizeof(conn_t));
	pthread_mutex_unlock(&pid_mutex);
	return c;
}

void free_conn(conn_t* c) {
	// for use by swift GUI
	if (c) free(c);
}

int get_num_conns() {
	// for use by swift GUI
	pthread_mutex_lock(&pid_mutex);
	int res = get_list_size(&gui_pid_list);
	pthread_mutex_unlock(&pid_mutex);
	return res;
}

int get_pid_changed() {
	// for use by swift GUI
	pthread_mutex_lock(&pid_mutex);
	int res=changed;
	pthread_mutex_unlock(&pid_mutex);
	return res;
}

void clear_pid_changed() {
	// for use by swift GUI
	pthread_mutex_lock(&pid_mutex);
	changed=0;
	pthread_mutex_unlock(&pid_mutex);
}

int find_pid(conn_raw_t *cr, char*name){
	// find name of process associated with a network connection tuple
	// (assumed to be an outgoing tuple, so src is local addr and dst
	// is remote).
	// called by sniffer_blocker on fast path.

	conn_t c;
	memcpy(&c.raw,cr,sizeof(conn_raw_t));
	pthread_mutex_lock(&pid_mutex);
	conn_t *res = in_list(&pid_list,&c,0); // list lookup only uses raw
	if (res) { // found it !
		strlcpy(name,res->name,BUFSIZE);
		pthread_mutex_unlock(&pid_mutex);
		INFO("found\n");
		return 1;
	}
	pthread_mutex_unlock(&pid_mutex);
	/*char dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
	INFO("find_pid() for %s ... not found\n", dn);*/
	INFO("not found\n");
	return 0;
}

//--------------------------------------------------------
//private.

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
	int st = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &proc, PROC_PIDT_SHORTBSDINFO_SIZE);
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
	// share the same fd are lumped together.
	// should hold lock when call this
	conn_t *item = (conn_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&item->raw.af,&item->raw.src_addr,sn,INET6_ADDRSTRLEN);
	robust_inet_ntop(&item->raw.af,&item->raw.dst_addr,dn,INET6_ADDRSTRLEN);
	char* temp = malloc(2*INET6_ADDRSTRLEN+64);
	sprintf(temp,"%s:%d-%s:%d",sn,item->raw.sport,dn,item->raw.dport);
	return temp;
}

int pid_cmp(const void* it1, const void* it2){
	// should hold lock when call this
	conn_t *item1 = (conn_t*) it1;
	conn_t *item2 = (conn_t*) it2;
	char * temp1 = pid_hash(item1);
	char * temp2 = pid_hash(item2);
	int res = (strcmp(temp1,temp2)==0);
	free(temp1); free(temp2);
	return res;
}

char* gui_pid_hash(const void *it) {
	// we add the domain name to hash to catch cases where
	// dns cache is updated to replace IP addr with name.
	// and remove source port, so treat conns which are same except for
	// source port as being the same
	// should hold lock when call this
	conn_t *item = (conn_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&item->raw.af,&item->raw.src_addr,sn,INET6_ADDRSTRLEN);
	robust_inet_ntop(&item->raw.af,&item->raw.dst_addr,dn,INET6_ADDRSTRLEN);
	char* temp = malloc(2*INET6_ADDRSTRLEN+strlen(item->domain)+64);
	sprintf(temp,"%s-%s:%d-%s",sn,dn,item->raw.dport,item->domain);
	return temp;
}

int gui_pid_cmp(const void* it1, const void* it2){
	// should hold lock when call this
	conn_t *item1 = (conn_t*) it1;
	conn_t *item2 = (conn_t*) it2;
	char * temp1 = gui_pid_hash(item1);
	char * temp2 = gui_pid_hash(item2);
	int res = (strcmp(temp1,temp2)==0);
	free(temp1); free(temp2);
	return res;
}

void init_pid_list() {
	// should hold lock when call this
	init_list(&pid_list,pid_hash,pid_cmp,0,"pid_list");
	init_list(&gui_pid_list,gui_pid_hash,gui_pid_cmp,0,"pid_list");
}

void dump_pidlist(list_t *l) {
	// should hold lock when call this
	int i;
	for (i=0; i<get_list_size(l);i++) {
		conn_t *b = get_list_item(l,i);
		//printf("%s %s(%s)\n",b->name,b->domain,b->dst_addr_name);
		printf("%s(%d): %s:%d -> %s(%s):%d udp=%d\n", b->name, b->pid, b->src_addr_name, b->raw.sport, b->domain, b->dst_addr_name, b->raw.dport, b->raw.udp);
	}
}

/*int coalesce_conn(list_t *l, conn_t *c) {
	// rather than showing multiple entries in GUI
	// for parallel connections by same app to same
	// destination/port pair, we coalesce them.

	for (int i=0; i<get_list_size(l);i++) {
		conn_t *c1 = get_list_item(l,i);
		if (strcmp(c1->name,c->name)!=0) continue;
		if (!are_addr_same(c1->raw.af, &c1->raw.dst_addr, &c->raw.dst_addr)) continue;
		if (!are_addr_same(c1->raw.af, &c1->raw.src_addr, &c->raw.src_addr)) continue;
		if (c1->raw.dport != c->raw.dport) continue;
		// found a match with same process name and dest:port (but might have
		// different source port
		return i;
	}
	return -1;
}*/

int find_fds(int pid, char* name, list_t* new_pid_list, list_t* new_gui_pid_list) {
	// Get the list of network connections for process PID
	
	// Figure out the size of the buffer needed to hold the list of open FDs
	int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (bufferSize == -1) {
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return 0;
	}

	struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
	if (!procFDInfo) {
		ERR("Out of memory. Unable to allocate buffer with %d bytes\n", bufferSize);
		return -1;
	}
	
	if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return 0;
	}
	int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
	
	for(int i = 0; i < numberOfProcFDs; i++) {
		conn_t c; // the new connection
		memset(&c,0,sizeof(c));
		
		if (procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET)
			continue; // not a socket fd
		struct socket_fdinfo socketInfo;
		memset(&socketInfo,0,sizeof(socketInfo));
		int res = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
		if (res != sizeof(struct socket_fdinfo)) continue;
		
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
			if (c.raw.af !=AF_INET) {
				//WARN("pid_conn(): mismatch between af's %d/%d\n",c.raw.af,AF_INET);
				// happens with matlab
				c.raw.af = AF_INET;
			}
			memcpy(&c.raw.src_addr, &sockinfo->insi_laddr.ina_46.i46a_addr4, sizeof(struct in_addr));
			memcpy(&c.raw.dst_addr, &sockinfo->insi_faddr.ina_46.i46a_addr4, sizeof(struct in_addr));
			if (is_ipv4_localhost(&c.raw.dst_addr))
				continue; // ignore localhost .
		} else { // IPv6
			if (c.raw.af !=AF_INET6) {
				//WARN("pid_conn(): mismatch between af's %d/%d\n",c.raw.af,AF_INET6);
				// happens with matlab
				c.raw.af = AF_INET6;
			}
			memcpy(&c.raw.src_addr, &sockinfo->insi_laddr.ina_6, sizeof(struct in6_addr));
			memcpy(&c.raw.dst_addr, &sockinfo->insi_faddr.ina_6, sizeof(struct in6_addr));
			if (is_ipv6_localhost(&c.raw.dst_addr))
				continue; // ignore localhost .
		}
		robust_inet_ntop(&c.raw.af, &c.raw.src_addr, c.src_addr_name, INET6_ADDRSTRLEN);
		robust_inet_ntop(&c.raw.af, &c.raw.dst_addr, c.dst_addr_name, INET6_ADDRSTRLEN);
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
		
		DEBUG2("%s(%d): %s:%d -> %s:%d udp=%d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.dst_addr_name, c.raw.dport, c.raw.udp);
		
		char* dns=lookup_dns_name(c.raw.af,c.raw.dst_addr);
		if (dns!=NULL) {
			strlcpy(c.domain,dns,BUFSIZE);
		} else {
			strlcpy(c.domain,c.dst_addr_name,INET6_ADDRSTRLEN);
		}
		// ignore child processes sharing conn of parent
		// - rely here on fact that parent will be processed
		// here before any child ...
		if (!in_list(new_pid_list, &c, 0)) {
			add_item(new_pid_list,&c,sizeof(conn_t));
		}
		
		// ignore child processes again, and also if several parallel
		// connections to same domain (differing only in src port) then hash
		// for gui_pid_list treats these as same so we just log first one in GUI pid list
		// (to keep GUI clean)
		//if ( (!in_list(new_gui_pid_list, &c, 0)) && (coalesce_conn(new_gui_pid_list,
		if (!in_list(new_gui_pid_list, &c, 0)) {
			add_item(new_gui_pid_list,&c,sizeof(conn_t));
		}
		
		pthread_mutex_lock(&pid_mutex);
		if (!in_list(&gui_pid_list, &c, 0)) {
			// we've added a new entry to pid list, flag to GUI if it needs to refresh
			changed = 1;
			//INFO("changed %s(%d): %s:%d -> %s(%s):%d udp=%d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.domain, c.dst_addr_name, c.raw.dport, c.raw.udp);
			//dump_pidlist(&gui_pid_list);
		}
		pthread_mutex_unlock(&pid_mutex);
	}
	free(procFDInfo);
	return 1;
}

int refresh_active_conns(int localhost) {
	// called to update list of active process
	// and network connectionsb(held in conns global var).
	// returns 1 if set of active connections has changed,
	// else 0, so that GUI knows whether it has to redraw itself
	
	// should hold lock when call this.
	// this and init_pid_list() are the only routines
	// which actually write to pid_list, the rest just read.

	DEBUG2("refresh_active_conns()\n");
		
	// we'll populate a new list with pid info -- this will take a little time.
	// then we copy this over to pid_list to update.  that way
	// the GUI etc only ever see a fully updated pis list, not partial updates
	// (which look nasty)
	list_t new_pid_list;
	init_list(&new_pid_list,pid_hash,pid_cmp,0,"new_pid_list");
	list_t new_gui_pid_list;
	init_list(&new_gui_pid_list,gui_pid_hash,gui_pid_cmp,0,"new_gui_pid_list");

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
		
		if (find_fds(pid, name, &new_pid_list, &new_gui_pid_list)<0) {
			free_list(&new_pid_list);
			free_list(&new_gui_pid_list);
			return 0;
		}
	}
	pthread_mutex_lock(&pid_mutex);
	if (get_list_size(&new_gui_pid_list) != get_list_size(&gui_pid_list)) {
		// could be that we have only removed some processes from pid list,
		// in which case changed=0 when get here
		//INFO("size changed: %d/%d\n",get_list_size(&new_gui_pid_list),get_list_size(&gui_pid_list));
		changed = 1;
	}
	// now copy new list over to pid_list and gui_pid_list.
	free_list(&pid_list);
	pid_list = new_pid_list;
	free_list(&gui_pid_list);
	gui_pid_list = new_gui_pid_list;
	pthread_mutex_unlock(&pid_mutex);
	return changed;
}






