//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

// maintains list of active processes and their network connections

// proc_info interface documentation: https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/sys/proc_info.h.auto.html

#include "pid_conn_info.h"

//global
static list_t pid_list=LIST_INITIALISER; // list of active pid's and network conns
static list_t gui_pid_list=LIST_INITIALISER; // filtered list for GUI
static Hashtable* pid_list_fdtab=NULL; // table for fast lookup of pid_list using socket fd
#define TABSIZE 1024
static list_t escapee_list=LIST_INITIALISER; // list of blocked yet active connections
static pthread_mutex_t escapee_mutex = PTHREAD_MUTEX_INITIALIZER;
static int escapee_thread_count=0;
#define ESCAPEEMAX 10 // max num of escapees we try to catch concurrently
static int changed = 0; // flag to GUI if pid list has changed

// cache of recent PIDs and their names
#define PID_CACHE_SIZE 2
static list_t last_pid_list=LIST_INITIALISER;
typedef struct last_pid_item_t {
	int pid;
	char name[MAXCOMLEN];;
} last_pid_item_t;

// thread globals
static pthread_cond_t pid_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t pid_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gui_pid_mutex = PTHREAD_MUTEX_INITIALIZER;
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
	struct timespec ts, now, timeout;
	# define PID_WATCHER_TIMEOUT 500 // in ms
	timeout.tv_sec = 0;
	#define NSEC_PER_SEC 1000000000
	timeout.tv_nsec = PID_WATCHER_TIMEOUT*(NSEC_PER_SEC/1000);

	int res=0;
	refresh_active_conns(0); // takes lock itself as needed
	for(;;) {
		clock_gettime(CLOCK_REALTIME, &now);
		ts = timespec_add(now,timeout);
		
		pthread_mutex_lock(&pid_mutex);
		res = 0;
		// release mutex and wait (either for timeout or a signal from]
		// sniffer_blocker that a new conn has started) ...
		while ((wakeup==0) && (res != ETIMEDOUT)) {
			res = pthread_cond_timedwait(&pid_cond, &pid_mutex, &ts);
			if ((res!=0) && (res!=ETIMEDOUT)) {
				WARN("pid_watcher() cond error: %s", strerror(errno));
			}
		}
		//printf("waking up, wakeup=%d\n",wakeup);
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
		init_pid_lists();
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
	//printf("signal sent\n");
}

void set_pid_watcher_hook(void (*hook)(void)) {
	// callback in watched.  used by sniffer_blocker to update its waiting list
	pid_watcher_hook = hook;
}

conn_t get_conn(int_sw row) {
	// for use by swift GUI
	conn_t c;
	memset(&c,0,sizeof(conn_t));
	pthread_mutex_lock(&gui_pid_mutex);
	if (row > get_list_size(&gui_pid_list)) {
		pthread_mutex_unlock(&gui_pid_mutex);
		return c;
	}
	memcpy(&c,get_list_item(&gui_pid_list,(size_t)row),sizeof(conn_t));
	pthread_mutex_unlock(&gui_pid_mutex);
	return c;
}

void free_conn(conn_t* c) {
	// for use by swift GUI
	if (c) free(c);
}

int_sw get_num_conns() {
	// for use by swift GUI
	pthread_mutex_lock(&gui_pid_mutex);
	int_sw res = (int_sw)get_list_size(&gui_pid_list);
	pthread_mutex_unlock(&gui_pid_mutex);
	//dump_connlist(&gui_pid_list);
	return res;
}

int_sw get_pid_changed() {
	// for use by swift GUI
	pthread_mutex_lock(&gui_pid_mutex);
	int res=changed;
	pthread_mutex_unlock(&gui_pid_mutex);
	return res;
}

void clear_pid_changed() {
	// for use by swift GUI
	pthread_mutex_lock(&gui_pid_mutex);
	changed=0;
	pthread_mutex_unlock(&gui_pid_mutex);
}

void print_escapees() {
	if (get_list_size(&escapee_list)>0) {
		INFO2("Escapees:\n");
		dump_connlist(&escapee_list);
	}
}

void cache_pid(int pid, char* name) {
	// we freshen cache using dtrace info since it gets most hits
	last_pid_item_t it;
	it.pid = pid; strlcpy(it.name,name,MAXCOMLEN);
	pthread_mutex_lock(&pid_mutex);
	// only add new pid if not already in list
	if (!in_list(&last_pid_list,&it,0)) {
		add_item(&last_pid_list,&it,sizeof(last_pid_item_t));
	}
	pthread_mutex_unlock(&pid_mutex);
}

int find_pid(conn_raw_t *cr, char*name, int syn){
	// find name of process associated with a network connection tuple
	// (assumed to be an outgoing tuple, so src is local addr and dst
	// is remote).
	// called by sniffer_blocker on fast path so needs to be efficient

	conn_t c;
	memcpy(&c.raw,cr,sizeof(conn_raw_t));
	pthread_mutex_lock(&pid_mutex);
	// lookup existing pid info list to see if connection is on it.
	// lookup only uses raw part of conn_t
	conn_t *res = in_list(&pid_list,&c,0); // list lookup only uses raw
	if (res) { // found it !
		strlcpy(name,res->name,MAXCOMLEN);
		pthread_mutex_unlock(&pid_mutex);
		INFO2("found\n");
		if (syn)
			stats.pidinfo_syn_hits++;
		else
			stats.pidinfo_hits++;
		cache_pid(res->pid, name);
		return 1;
	}
	if (syn)
		stats.pidinfo_syn_misses++;
	else
		stats.pidinfo_misses++;

	pthread_mutex_unlock(&pid_mutex);
	// we cache last few PIDs and then try to
	// do a targetted refresh of their network conns here.
	// if we get a hit then we catch pid name earlier,
	// at the cost of slightly longer processing time on
	// sniffer_blocker fast path, so would want to keep number of PIDs checked *small*
	// might as well stash pid info in pid_list while we're at it,
	// in case it contains multiple new connections.
	
	struct timeval start; gettimeofday(&start, NULL);
	list_t *l = &pid_list;
	
	pthread_mutex_lock(&pid_mutex);
	for (size_t i = 0; i< get_list_size(&last_pid_list); i++) {
		last_pid_item_t *it = get_list_item(&last_pid_list,i);
		if (it->pid<=0) continue; // shouldn't happen
		
		if (find_fds(it->pid, it->name, pid_list_fdtab, l, pid_list_fdtab, NULL)!=1) {
			continue; // cached pid is a dud, probably cached process has died
		} else if (in_list(l,&c,0)) { // list lookup only uses raw
			pthread_mutex_unlock(&pid_mutex);
			strlcpy(name,it->name,MAXCOMLEN);
			if (syn)
				stats.pidinfo_syn_cachehits++;
			else
				stats.pidinfo_cachehits++;
			struct timeval end; gettimeofday(&end, NULL);
			double t=(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0;
			cm_add_sample_lock(&stats.cm_t_pidinfo_cache_hit,t);
			INFO2("found using last_pid.\n");
			return 1;
		}
	}
	struct timeval end; gettimeofday(&end, NULL);
	double t=(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0;
	cm_add_sample_lock(&stats.cm_t_pidinfo_cache_miss,t);	pthread_mutex_unlock(&pid_mutex);
	if (syn)
		stats.pidinfo_syn_cachemisses++;
	else
		stats.pidinfo_cachemisses++;

	// failed. we'll now trigger refresh of pid_info by watcher thread.
	// nb: there's a possibility that will miss connection if it dies before
	// watcher completes refresh
	INFO2("not found.\n");
	return 0;
}

//--------------------------------------------------------
//private.

int get_pid_name(int pid, char* name) {
	// use syscall to get process name associated with pid
	struct proc_bsdshortinfo proc;
	int st = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &proc, PROC_PIDT_SHORTBSDINFO_SIZE);
	if (st != PROC_PIDT_SHORTBSDINFO_SIZE) {
		//INFO("Cannot get process info for PID %d, likely has died.\n",pid);
		return -1;
	}
	strlcpy(name,proc.pbsi_comm,MAXCOMLEN);
	return 0;
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
	sprintf(temp,"%s-%s:%u-%s",sn,dn,item->raw.dport,item->domain);
	return temp;
}

char* pid_hash(const void *it) {
	last_pid_item_t *item = (last_pid_item_t*) it;
	char* temp = malloc(STR_SIZE);
	sprintf(temp,"%d",item->pid);
	return temp;
}

char* pid_fdtab_hash(const int fd, const int pid) {
	char* temp = malloc(STR_SIZE);
	sprintf(temp,"%d:%d",pid,fd);
	return temp;
}

void init_pid_lists() {
	// should hold lock when call this
	init_list(&pid_list,conn_hash,NULL,0,-1,"pid_list");
	init_list(&gui_pid_list,gui_pid_hash,NULL,0,-1,"pid_list");
	init_list(&last_pid_list,pid_hash,NULL,1,PID_CACHE_SIZE,"last_pid_list");
	pid_list_fdtab = hashtable_new(TABSIZE);
	init_list(&escapee_list,conn_hash,NULL,1,-1,"escapee_list");
}

int find_fds(int pid, char* name, Hashtable* old_pid_list_fdtab, list_t* new_pid_list, Hashtable* new_pid_list_fdtab, list_t* new_gui_pid_list) {
	// Refresh the list of network connections for process with PID pid.
	// can call this function without holding lock, and also
	// ok to call with lock already held -- it will reuse lock/take new lock
	// as needed.
	
	// Figure out the size of the buffer needed to hold the list of open FDs
	int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (bufferSize == -1) {
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return 0;
	}

	struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc((size_t)bufferSize);
	if (!procFDInfo) {
		ERR("Out of memory. Unable to allocate buffer with %d bytes\n", bufferSize);
		return -1;
	}
	
	if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return 0;
	}
	size_t numberOfProcFDs = (size_t)bufferSize / PROC_PIDLISTFD_SIZE;
	
	for(int i = 0; i < numberOfProcFDs; i++) {
		conn_t c; // the new connection
		memset(&c,0,sizeof(c));
		
		if (procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET)
			continue; // not a socket fd
			
		// an optimisation.  if procFDInfo[i].proc_fd already known
		// we can just grab its info and copy over, saving on call to proc_pidfdinfo()
		// which is expensive
		// NB: reuse of file descriptors means that can make mistakes here e.g.
		// if between calls to here a process closes a connection and new one is
		// opened (to new destination) but has the same fd.
		int match=0;
		/*int res=pthread_mutex_trylock(&pid_mutex);
		char* key = pid_fdtab_hash(procFDInfo[i].proc_fd,pid);
		conn_t* it = hashtable_get(old_pid_list_fdtab, key);
		free(key);
		if (it != NULL) { // got a match
			memcpy(&c,it,sizeof(conn_t));
			match = 1;
		}
		if (res != EBUSY) {
			// we took the lock ourselves, so let's release it
			pthread_mutex_unlock(&pid_mutex);
		}*/
		if (!match) {
			// we need to call proc_pidfdinfo() to get the connection info
			struct socket_fdinfo socketInfo;
			memset(&socketInfo,0,sizeof(socketInfo));
			int res = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
			if (res != sizeof(struct socket_fdinfo)) continue;
			
			int state = socketInfo.psi.soi_proto.pri_tcp.tcpsi_state;
			if ((socketInfo.psi.soi_kind != SOCKINFO_TCP)
					&& (socketInfo.psi.soi_kind != SOCKINFO_IN)) continue; // unix sock or the like
			if ((socketInfo.psi.soi_kind == SOCKINFO_TCP) && (state != TSI_S_ESTABLISHED))
				continue; // TCP, but not an established connection. don't log it
			
			c.pid=pid; c.fd=procFDInfo[i].proc_fd;
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
			c.raw.sport =  ntohs(sockinfo->insi_lport);
			c.raw.dport = ntohs(sockinfo->insi_fport);
			
			// we only log UDP to port 443 just now (likely QUIC)
			c.raw.udp = (socketInfo.psi.soi_kind == SOCKINFO_IN)
			&& (c.raw.dport == 443);
			
			DEBUG2("%s(%d): %s:%u -> %s:%u udp=%d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.dst_addr_name, c.raw.dport, c.raw.udp);
		}
		
		// lookup domain name for connection.  do this even for existing connections
		// as might have sniffed new dns packet since first saw connection
		char* dns=lookup_dns_name(c.raw.af,c.raw.dst_addr);
		if (dns!=NULL) {
			strlcpy(c.domain,dns,MAXDOMAINLEN);
		} else {
			strlcpy(c.domain,c.dst_addr_name,INET6_ADDRSTRLEN);
		}
		
		// ignore child processes sharing conn of parent
		// - rely here on fact that parent will be processed
		// here before any child ...
		// nb: if new_pid_list=old_pid_list this is fine, will skip duplicates
		if (!in_list(new_pid_list, &c, 0)) {
			add_item(new_pid_list,&c,sizeof(conn_t));
			// get a pointer to new table entry ...
			conn_t *it = in_list(new_pid_list,&c,0);
			// and add it to fd lookup table
			char* key = pid_fdtab_hash(procFDInfo[i].proc_fd,pid);
			hashtable_put(new_pid_list_fdtab, key, it);
			free(key);
		}
		
		// is this a connection which outght to have been blocked (and "escapee") ?
		bl_item_t b;
		strlcpy(b.name,name,MAXCOMLEN);
		strlcpy(b.domain,c.domain,MAXDOMAINLEN);
		strlcpy(b.addr_name,c.dst_addr_name,INET6_ADDRSTRLEN);
		// get log entry for this item, if it exists.
		log_line_t *l = find_log_by_conn(name,&c.raw,0);
		if ( (((l!=NULL)&&(l->blocked!=0)) || (is_blocked(&b)!=0)) && (c.raw.udp==0)) {
			// its an active connection that is supposed to have been blocked
			pthread_mutex_lock(&escapee_mutex);
			if ( (!in_list(&escapee_list,&c,0)) && (escapee_thread_count<ESCAPEEMAX)) {
				// a new escapee, add to the active list ...
				add_item(&escapee_list,&c,sizeof(conn_t));
				pthread_mutex_unlock(&escapee_mutex);
				conn_t *e = malloc(sizeof(conn_t));
				memcpy(e,&c,sizeof(conn_t));
				// get the initial seq number of conn from log, if possible.
				if (l==NULL) {
					//INFO("escapee not in log %s(%d): %s:%u -> %s(%s):%u udp=%d,l=%d\n", c.name, c.pid, c.src_addr_name,c.raw.sport, c.domain, c.dst_addr_name, c.raw.dport, c.raw.udp,l==NULL);
					// guess ! the seq number is used to prompt local to send a pkt
					// when connection is idle so that we can get the real seq number
					// from it. its not needed for conns sending pkts already. this will
					// probably fail unless connection is already sending pkts
					e->raw.seq = (uint32_t)rand(); e->raw.ack = (uint32_t)rand();
					stats.escapees_not_in_log++;
				} else {
					// we get the seq number from syn-ack in log ...
					e->raw.seq =l->raw.seq; e->raw.ack =l->raw.ack;
					struct timeval start; gettimeofday(&start, NULL);
					#define TIMEOUT 10 // 10secs
					if (start.tv_sec - l->raw.ts.tv_sec < TIMEOUT) {
						// keep some stats
						stats.num_escapees++;
					} else {
						//an ancient connections.  seq number is maybe too old now,
						// should we just choose a randome one, or otherwise adjust it ?
						stats.stale_escapees++;
					}
				}
				// and ask helper to catch this "escapee" connection
				pthread_t escapee_thread;
				pthread_create(&escapee_thread,NULL,catch_escapee,e);
				cm_add_sample_lock(&stats.cm_escapee_thread_count,escapee_thread_count);
				// escapee_thread will now remove from escapee_list and free (e)
			} else {
				pthread_mutex_unlock(&escapee_mutex);
			}
		}
		
		// ignore child processes again, and also if several parallel
		// connections to same domain (differing only in src port) then hash
		// for gui_pid_list treats these as same so we just log first one in GUI pid list
		// (to keep GUI clean)
		if (new_gui_pid_list) {
			if (!in_list(new_gui_pid_list, &c, 0)) {
				add_item(new_gui_pid_list,&c,sizeof(conn_t));
			}
			int res=pthread_mutex_trylock(&gui_pid_mutex);
			if (!in_list(&gui_pid_list, &c, 0)) {
				// we've added a new entry to pid list, flag to GUI if it needs to refresh
				changed = 1;
				//INFO("changed %s(%d): %s:%u -> %s(%s):%u udp=%d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.domain, c.dst_addr_name, c.raw.dport, c.raw.udp);
		  	//dump_connlist(&gui_pid_list);
			}
			if (res != EBUSY) {
				pthread_mutex_unlock(&gui_pid_mutex);
			}
		}
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

	DEBUG2("refresh_active_conns()\n");
		
	// we'll populate a new list with pid info -- this will take a little time.
	// then we copy this over to pid_list to update.  that way
	// the GUI etc only ever see a fully updated pis list, not partial updates
	// (which look nasty)
	list_t new_pid_list; init_list(&new_pid_list,conn_hash,NULL,0,-1,"new_pid_list");
	list_t new_gui_pid_list; init_list(&new_gui_pid_list,gui_pid_hash,NULL,0,-1,"new_gui_pid_list");
	Hashtable *new_pid_list_fdtab = hashtable_new(TABSIZE);
	
	// get list of current processes
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);

	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = (size_t)bufsize / sizeof(pid_t);

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
		
		if (find_fds(pid, name, pid_list_fdtab, &new_pid_list, new_pid_list_fdtab, &new_gui_pid_list)<0) {
			free_list(&new_pid_list);
			free_list(&new_gui_pid_list);
			hashtable_free(new_pid_list_fdtab);
			return 0;
		}
	}
	pthread_mutex_lock(&gui_pid_mutex);
	if (get_list_size(&new_gui_pid_list) != get_list_size(&gui_pid_list)) {
		// could be that we have only removed some processes from pid list,
		// in which case changed=0 when get here
		//INFO("size changed: %d/%d\n",get_list_size(&new_gui_pid_list),get_list_size(&gui_pid_list));
		changed = 1;
	}
	free_list(&gui_pid_list); gui_pid_list = new_gui_pid_list;
	pthread_mutex_unlock(&gui_pid_mutex);
	// now copy new list over to pid_list
	pthread_mutex_lock(&pid_mutex);
	free_list(&pid_list); pid_list = new_pid_list;
	hashtable_free(pid_list_fdtab); pid_list_fdtab = new_pid_list_fdtab;
	pthread_mutex_unlock(&pid_mutex);
		
	return changed;
}

#define CATCHER_PORT 5
#include "helper.h"
void *catch_escapee(void *ptr) {
	pthread_mutex_lock(&escapee_mutex);
	escapee_thread_count++;
	pthread_mutex_unlock(&escapee_mutex);

	conn_t *e = (conn_t*)ptr;
	struct timeval start; gettimeofday(&start, NULL);

	int c_sock;
	// block here if helper is busy with killing a connection
	if ( (c_sock=connect_to_helper(CATCHER_PORT,1))<0 ) {
		return NULL;  //either helper has gone away or listen queue for escapees is full
	}
	//struct timeval end0; gettimeofday(&end0, NULL);
	//printf("catch escapee connected, %fs\n",(end0.tv_sec - start.tv_sec) +(end0.tv_usec - start.tv_usec)/1000000.0);

	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	ssize_t res;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	if ( (res=send(c_sock, &e->pid, sizeof(int),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.af, sizeof(int),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.dst_addr, sizeof(struct in6_addr),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.dport, sizeof(uint16_t),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.ack, sizeof(uint32_t),0) )<=0) goto err;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	int8_t ok=0; read(c_sock, &ok, 1); // wait here until helper is done
	// remove escapee from active list, will be re-added if conn still exists
	// next time find_fds() is called.
	struct timeval end; gettimeofday(&end, NULL);
	double t=(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0;
	char *result="FAILED to stop";
	if (ok==1) {
		result="STOPPED";
		stats.escapees_hits++;
		cm_add_sample_lock(&stats.cm_t_escapees_hits,t);
	} else if (ok==-1) {
		result="NOT FOUND";
	} else {
		stats.escapees_misses++;
		cm_add_sample_lock(&stats.cm_t_escapees_misses,t);
	}
	INFO("escapee %s(%d) fd=%d %s:%u -> %s(%s):%u ack=%u,udp=%d: %s. t=%fs\n", e->name, e->pid, e->fd,e->src_addr_name, e->raw.sport, e->domain, e->dst_addr_name, e->raw.dport, e->raw.ack,e->raw.udp,result,t);
	del_item(&escapee_list,e);
	free(e);
	close(c_sock);
	pthread_mutex_lock(&escapee_mutex);
	escapee_thread_count--;
	pthread_mutex_unlock(&escapee_mutex);
	return NULL;
	
err:
	WARN("write escapee: %s", strerror(errno));
	del_item(&escapee_list,e);
	free(e);
	close(c_sock);
	pthread_mutex_lock(&escapee_mutex);
	escapee_thread_count--;
	pthread_mutex_unlock(&escapee_mutex);
	return NULL;
}


