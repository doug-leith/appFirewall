//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

// maintains list of active processes and their network connections

// proc_info interface documentation: https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/sys/proc_info.h.auto.html
//https://opensource.apple.com/source/xnu/xnu-3248.60.10/bsd/kern/proc_info.c.auto.html

#include "pid_conn_info.h"

//globals
static pid_info_t pid_info = PID_INFO_INITIALSER;

// thread globals
static pthread_cond_t pid_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t pid_mutex = MUTEX_INITIALIZER;
static pthread_mutex_t gui_pid_mutex = MUTEX_INITIALIZER;
static pthread_mutex_t escapee_mutex = MUTEX_INITIALIZER;
// always take pid_mutex lock before gui_pid_mutex to avoid deadlocks,
// also pid_mutex lock before escapee_mutex
static pthread_t pid_thread; // handle to pid watcher thread
static int pid_thread_started = 0; // indicates whether pid watcher thread already running
static int wakeup = 0, force = 0, force_full_refresh=0;
static void (*pid_watcher_hook)(void) = NULL;

//--------------------------------------------------------
// swift interface

// thread safety for pid_list:
// -pid_watcher runs in its own thread and calls refresh_active_conns().
// -get_gui_conn(),get_num_gui_conns(),get_pid_changed(),set_pid_changed()
// are called fro, swift ActiveConnsViewController which runs in a separate
// thread
// -find_pid() is called by sniffer_blocker listener (via
// create_blockitem_from_addr())
// from its own thread, and also from pid_watcher_hook()

void *pid_watcher(void *ptr) {
	// runs in its own thread to keep pid_list uodated
	struct timespec ts, now, timeout;
	struct timeval last_full_refresh;
	timeout.tv_sec = 0;
	#define NSEC_PER_SEC 1000000000
	timeout.tv_nsec = PID_WATCHER_TIMEOUT*(NSEC_PER_SEC/1000);

	struct timeval t_last;
	memset(&t_last,0,sizeof(struct timeval));
	
	int res=0;
	refresh_active_conns(1); // takes lock itself as needed
	gettimeofday(&last_full_refresh, NULL);
	for(;;) {
		clock_gettime(CLOCK_REALTIME, &now);
		ts = timespec_add(now,timeout);
		
		TAKE_LOCK(&pid_mutex,"pid_watcher");
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

		int full_refresh = 0;
		struct timeval t; gettimeofday(&t, NULL);
		double elapsed = (t.tv_sec - last_full_refresh.tv_sec) +(t.tv_usec - last_full_refresh.tv_usec)/1000000.0;
		if ((elapsed > REFRESH_TIMEOUT)||force_full_refresh) {
			// nb: we force a full refresh fairly often so as to correct any temporary
			// mistakes in find_fds() caused by reuse of file descriptors, even though
			// these are pretty rare
			gettimeofday(&last_full_refresh, NULL);;
			full_refresh=1; force_full_refresh=0;
		}
		// if we're making many mistakes, fall back to always
		// doing a full refresh, just to be careful
		int sum = stats.fdtab_same + stats.fdtab_changed;
		if ((sum>100) && (stats.fdtab_destchanged*1.0/sum > REFRESH_THRESH)) {
			full_refresh=1;force_full_refresh=0;
		}
		// this call consumes >85% of execution time
		refresh_active_conns(full_refresh); // will take lock
		
		//struct timeval t;
		gettimeofday(&t, NULL);
		elapsed = (t.tv_sec - t_last.tv_sec) +(t.tv_usec - t_last.tv_usec)/1000000.0;
		// should probably try to tune this timeout
		// -- if too small then we call escapee_catcher for conns which
		// have already been killed by RSTs but which we haven't noticed
		// that yet.  if too large we have to do more work to kill conn
		// (since ack seq number is stale), but we call escapee_catcher
		// and create a backlog of work.
		// force=1 when we've just stopped an escapee and so want to
		// check if there are any others without adding delay
		if (force || (elapsed > ESCAPEE_TIMEOUT)) {
			find_escapees();
			t_last = t;
			TAKE_LOCK(&pid_mutex,"pid_watcher #2");
			force = 0;
			pthread_mutex_unlock(&pid_mutex);
		}
		
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

void signal_pid_watcher(int force_find_escapee, int full_refresh) {
	// ask watcher to refresh pid_list
	TAKE_LOCK(&pid_mutex,"signal_pid_watcher");
	wakeup = 1; force = force_find_escapee; force_full_refresh=full_refresh;
	pthread_cond_signal(&pid_cond);
	pthread_mutex_unlock(&pid_mutex);
	//printf("signal sent\n");
}

void set_pid_watcher_hook(void (*hook)(void)) {
	// callback in watched.  used by sniffer_blocker to update its waiting list
	pid_watcher_hook = hook;
}

char* gui_pid_hash(const void *it) {
	// we add the domain name to hash to catch cases where
	// dns cache is updated to replace IP addr with name.
	// and remove source port, so treat conns which are same except for
	// source port as being the same
	conn_t *item = (conn_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&item->raw.af,&item->raw.src_addr,sn,INET6_ADDRSTRLEN);
	robust_inet_ntop(&item->raw.af,&item->raw.dst_addr,dn,INET6_ADDRSTRLEN);
	size_t len = 2*INET6_ADDRSTRLEN+strnlen(item->domain,MAXDOMAINLEN)+64;
	char* temp = malloc(len);
	snprintf(temp,len,"%s-%s:%u-%s",sn,dn,item->raw.dport,item->domain);
	return temp;
}

void update_gui_pid_list() {
	// called by swift GUI
	
	TAKE_LOCK(&gui_pid_mutex,"update_gui_pid_list");
	free_list(&pid_info.gui_pid_list);
	init_list(&pid_info.gui_pid_list, gui_pid_hash,NULL,0,-1,"gui_pid_list");
	pthread_mutex_unlock(&gui_pid_mutex);

	// we take lock for full loop so that we don't show
	// partial updates in GUI.
	TAKE_LOCK(&pid_mutex,"get_conn");
	for (size_t j=0; j< get_list_size(&pid_info.pid_list); j++) {
		conn_t *c = get_list_item(&pid_info.pid_list, j);
		// ignore child processes, and also if several parallel
		// connections to same domain (differing only in src port) then hash
		// for gui_pid_list treats these as same so we just log first one in GUI
		// pid list (to keep GUI clean)
		TAKE_LOCK(&gui_pid_mutex,"update_gui_pid_list");
		if (!in_list(&pid_info.gui_pid_list, c, 0)) {
			add_item(&pid_info.gui_pid_list,c,sizeof(conn_t));
		}
		pthread_mutex_unlock(&gui_pid_mutex);
	}
	pthread_mutex_unlock(&pid_mutex);
}

conn_t get_gui_conn(int_sw row) {
	// for use by swift GUI
	conn_t c;
	memset(&c,0,sizeof(conn_t));
	if (row > get_list_size(&pid_info.gui_pid_list)) {
		return c;
	}
	memcpy(&c,get_list_item(&pid_info.gui_pid_list,(size_t)row),sizeof(conn_t));

	return c;
}

void free_conn(conn_t* c) {
	// for use by swift GUI
	if (c) free(c);
}

int_sw get_num_gui_conns() {
	// for use by swift GUI
	int_sw res = (int_sw)get_list_size(&pid_info.gui_pid_list);
	//dump_connlist(&gui_pid_list);
	return res;
}

int_sw get_pid_changed() {
	// for use by swift GUI
	TAKE_LOCK(&pid_mutex,"get_pid_changed");
	int res=pid_info.changed;
	pthread_mutex_unlock(&pid_mutex);
	return res;
}

void clear_pid_changed() {
	// for use by swift GUI
	TAKE_LOCK(&pid_mutex,"clear_pid_changed");
	pid_info.changed=0;
	pthread_mutex_unlock(&pid_mutex);
}

void print_escapees() {
	// called by swift GUI
	TAKE_LOCK(&escapee_mutex,"print_escapees");
	if (get_list_size(&pid_info.escapee_list)>0) {
		INFO2("Escapees:\n");
		dump_connlist(&pid_info.escapee_list);
	}
	pthread_mutex_unlock(&escapee_mutex);
}

void cache_pid(int pid, char* name) {
	// we freshen cache using dtrace info since it gets most hits
	last_pid_item_t it;
	it.pid = pid; strlcpy(it.name,name,MAXCOMLEN);

	TAKE_LOCK(&pid_mutex,"cache_pid");
	// only add new pid if not already in list
	if (!in_list(&pid_info.last_pid_list,&it,0)) {
		add_item(&pid_info.last_pid_list,&it,sizeof(last_pid_item_t));
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
	TAKE_LOCK(&pid_mutex,"find_pid");
	// lookup existing pid info list to see if connection is on it.
	// lookup only uses raw part of conn_t
	conn_t *res = in_list(&pid_info.pid_list,&c,0); // list lookup only uses raw
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

	// we cache last few PIDs and then try to
	// do a targetted refresh of their network conns here.
	// if we get a hit then we catch pid name earlier,
	// at the cost of slightly longer processing time on
	// sniffer_blocker fast path, so would want to keep number of PIDs checked
	// *small*. might as well stash pid info in pid_list while we're at it,
	// in case it contains multiple new connections.
	
	struct timeval start; gettimeofday(&start, NULL);
	list_t *l = &pid_info.pid_list;
	
	// we hold pid_mutex lock here
	for (size_t i = 0; i< get_list_size(&pid_info.last_pid_list); i++) {
		last_pid_item_t *it = get_list_item(&pid_info.last_pid_list,i);
		if (it->pid<=0) continue; // shouldn't happen
		
		// call here to find_fds() consumes >90% of execution time of find_pid()
		// to try to save time we don't do a full refresh of conns but instead
		// reuse conn details of existing file descriptors.  will cause a
		// mistake if fd has been reused.
		if (find_fds(it->pid, it->name, l, 0)!=1) {
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
	pthread_mutex_unlock(&pid_mutex);
	struct timeval end; gettimeofday(&end, NULL);
	double t=(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0;
	cm_add_sample_lock(&stats.cm_t_pidinfo_cache_miss,t);
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

pid_info_t* get_pid_info() {
	return &pid_info;
}

int get_pid_name(int pid, char* name, uint32_t *status) {
	// use syscall to get process name associated with pid
	struct proc_bsdshortinfo proc;
	int st = (pid_info.proc_pidinfo)(pid, PROC_PIDT_SHORTBSDINFO, 1, &proc, PROC_PIDT_SHORTBSDINFO_SIZE);
	if (st != PROC_PIDT_SHORTBSDINFO_SIZE) {
		//INFO("Cannot get process info for PID %d, likely has died.\n",pid);
		return -1;
	}
	// surprisingly, some process names have trailing whitespace
	char n[MAXCOMLEN];
	strlcpy(n,proc.pbsi_comm,MAXCOMLEN);
	char* clean_n = trimwhitespace(n);
	strlcpy(name,clean_n,MAXCOMLEN);
	if (status != NULL) {
		// return status of process (zombie etc)
		*status = proc.pbsi_status;
	}
	return 0;
}

int get_pid_path(int pid, char* path, int size) {
	// use syscall to get path of executable associated with pid
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE+1];
	memset(pathbuf,0,PROC_PIDPATHINFO_MAXSIZE+1);
	int res = proc_pidpath(pid, pathbuf, PROC_PIDPATHINFO_MAXSIZE);
	if (res <= 0) { // error, likely pid has gone away
		//WARN("get_pid_path(): %s\n",strerror(errno));
		return -1;
	}
	strlcpy(path,pathbuf,size);
	return 0;
}

char* get_name_path(char* name) {
	// get executable path associated with process name
	pid_path_name_t path_name; memset(&path_name,0,sizeof(pid_path_name_t));
	strlcpy(path_name.name,name,MAXCOMLEN);
	pid_path_name_t* res = in_list(&pid_info.pid_path_list,&path_name,0);
	if (res == NULL)
		return "";
	else return res->path;
}

char* pid_hash(const void *it) {
	last_pid_item_t *item = (last_pid_item_t*) it;
	char* temp = malloc(STR_SIZE);
	snprintf(temp,STR_SIZE,"%d",item->pid);
	return temp;
}

char* pid_fdtab_hash(const int fd, const int pid) {
	char* temp = malloc(STR_SIZE);
	snprintf(temp,STR_SIZE,"%d:%d",pid,fd);
	return temp;
}

char* pid_path_name_hash(const void *it) {
 pid_path_name_t *item = (pid_path_name_t*)it;
	char* temp = malloc(PROC_PIDPATHINFO_MAXSIZE+1);
	snprintf(temp,PROC_PIDPATHINFO_MAXSIZE+1,"%s",item->name);
	return temp;
}

void init_pid_lists() {
	// should hold lock when call this
	init_list(&pid_info.pid_list,conn_hash,NULL,0,-1,"pid_list");
	init_list(&pid_info.gui_pid_list,gui_pid_hash,NULL,0,-1,"pid_list");
	init_list(&pid_info.last_pid_list,pid_hash,NULL,1,PID_CACHE_SIZE,"last_pid_list");
	init_list(&pid_info.escapee_list,conn_hash,NULL,1,-1,"escapee_list");
	init_list(&pid_info.pid_path_list,pid_path_name_hash,NULL,1,-1,"pid_path_list");
}

conn_t * find_conn(int pid, int fd) {
	// given PID and fd try to find connection in pid_list
	// -- replace this with a table lookup to speed things up ?
	for (size_t j = 0; j<get_list_size(&pid_info.pid_list); j++) {
		conn_t *it = get_list_item(&pid_info.pid_list,j);
		if (it->pid != pid) continue;
		if (it->fd !=fd) continue;
		return it;
	}
	return NULL;
}

int find_fds(int pid, char* name, list_t* new_pid_list, int full_refresh) {
	// Refresh the list of network connections for process with PID pid.
	// Updated list of conns is returned in new_pid_list.
	
	// Figure out the size of the buffer needed to hold the list of open FDs
	// this call costs about 10% of execution time of find_fds
	int bufferSize = (pid_info.proc_pidinfo)(pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (bufferSize < 0) {
		// probably process has stopped
		WARN("Unable to get open file handles for PID %d\n", pid);
		return 0;
	}
	if (bufferSize == 0) return 0; // process has no open files

	struct proc_fdinfo *procFDInfo =  malloc((size_t)bufferSize);
	if (!procFDInfo) {
		ERR("Out of memory. Unable to allocate buffer with %d bytes\n", bufferSize);
		return -1;
	}
	
	// this is second most time-consuming part of find_fds (the first is proc_fdinfo), takes around 10% of execution time
	if ((pid_info.proc_pidinfo)(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize) < 0){
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
		// we can just grab its info and copy over, saving on call to
		// proc_pidfdinfo(), which is expensive
		// NB: reuse of file descriptors means that can make mistakes here e.g.
		// if between calls to here a process closes a connection and new one is
		// opened (to new destination) but has the same fd.
		int match=0;
		conn_t *prev_c = find_conn(pid, procFDInfo[i].proc_fd);
		if ((!full_refresh) && (prev_c != NULL)) { // found a match
			// save time and reuse the old fd details
			match = 1;
			memcpy(&c,prev_c,sizeof(conn_t));
		}
		if (!match) {
			// we need to call proc_pidfdinfo() to get the connection info
			// nb: this call is where almost all (>70%) of the time is spent
			// in find_fds(), rest of routine is much faster
			struct socket_fdinfo socketInfo;
			memset(&socketInfo,0,sizeof(socketInfo));
			int res = (pid_info.proc_pidfdinfo)(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, 	&socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
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
			if (strncmp(mask, c.src_addr_name, strnlen(mask,INET6_ADDRSTRLEN)) == 0) {
				continue; // ignore IPv6 link local addresses
			}
			mask="::";
			if (strncmp(mask, c.src_addr_name, strnlen(mask,INET6_ADDRSTRLEN)) == 0) {
				continue; // null IPv6 address, happens with Skype
			}

			c.raw.sport =  ntohs(sockinfo->insi_lport);
			c.raw.dport = ntohs(sockinfo->insi_fport);
			
			// we only log UDP to port 443 just now (likely QUIC)
			//c.raw.udp = (socketInfo.psi.soi_kind == SOCKINFO_IN)
			//&& (c.raw.dport == 443);
			c.raw.udp = (socketInfo.psi.soi_kind == SOCKINFO_IN);
			
			DEBUG2("%s(%d): %s:%u -> %s:%u udp=%d\n", c.name, c.pid, c.src_addr_name, c.raw.sport, c.dst_addr_name, c.raw.dport, c.raw.udp);
		}

		// let's log how many times the previous details for an fd
		// are accurate i.e. the fd has not been reallocated.
		if ((full_refresh) && (prev_c != NULL)) {
			char *temp_prev = conn_hash(prev_c);
			char *temp_c = conn_hash(&c);
			if (strcmp(temp_prev,temp_c)==0)
				stats.fdtab_same++; // match is good
			else {
				stats.fdtab_changed++; // fd has been reused, bad news
				INFO2("FD CHANGED: for %s was %s now %s\n", c.name, temp_prev, temp_c);
				if (!are_addr_same(c.raw.af, &c.raw.dst_addr, &prev_c->raw.dst_addr))
					stats.fdtab_destchanged++;
			}
			free(temp_prev); free(temp_c);
		}

		// lookup domain name for connection.  do this even for existing connections
		// as might have sniffed new dns packet since first saw connection
		char* dns=lookup_dns_name(c.raw.af,c.raw.dst_addr);
		if (dns!=NULL) {
			strlcpy(c.domain,dns,MAXDOMAINLEN);
			free(dns);
		} else {
			strlcpy(c.domain,c.dst_addr_name,INET6_ADDRSTRLEN);
		}
		
		// ignore child processes sharing conn of parent
		// - rely here on fact that parent will be processed
		// here before any child ...
		// nb: if new_pid_list=old_pid_list this is fine, will skip duplicates
		if (!in_list(new_pid_list, &c, 0)) {
			add_item(new_pid_list,&c,sizeof(conn_t));
			TAKE_LOCK(&gui_pid_mutex,"find_fds() gui_pid_mutex");
			if (!in_list(&pid_info.gui_pid_list, &c, 0)) {
				pid_info.changed = 1;
			}
			pthread_mutex_unlock(&gui_pid_mutex);
		}
	}
	free(procFDInfo);
	return 1;
}

int refresh_active_conns(int full_refresh) {
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
	list_t new_pid_list; init_list(&new_pid_list,conn_hash,NULL,0,-1,"pid_list");
	
	// get list of current processes
	int bufsize = (pid_info.proc_listpids)(PROC_ALL_PIDS, 0, NULL, 0);

	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  (pid_info.proc_listpids)(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = (size_t)bufsize / sizeof(pid_t);
	// now walk through them
	//num_conns = 0;
	int j;
	for (j=0; j< num_pids; j++) {
		int pid = pids[j];
		// get app name associated with process
		// this call consumes around 10% of executiin time of refresh_active_conns()
		pid_path_name_t path_name; memset(&path_name,0,sizeof(pid_path_name_t));
		if (get_pid_name(pid, path_name.name, NULL)<0) {
			// problem getting name for PID, probably process has stopped
			// between call to proc_listpids() above and our call to get_pid_name()
			continue;
		}
		// add path to executable to table (doesn't change, so no need to
		// do expensive syscall every time)
		if (!in_list(&pid_info.pid_path_list,&path_name,0)) {
			// new process, get the executable path
			if (get_pid_path(pid, path_name.path, PROC_PIDPATHINFO_MAXSIZE+1)==0) {
				add_item(&pid_info.pid_path_list,&path_name,sizeof(pid_path_name_t));
			} else {
				//error, probably process has stopped.  not fatal, continue on
			}
		}
		
		// this call to find_fds() consumes >75% of execution time of
		// refresh_active_conns()
		TAKE_LOCK(&pid_mutex,"find_fds pid_mutex");
		if (find_fds(pid, path_name.name, &new_pid_list, full_refresh)<0) {
			pthread_mutex_unlock(&pid_mutex);
			free_list(&new_pid_list);
			return 0;
		}
		pthread_mutex_unlock(&pid_mutex);
	}
	// now copy new list over to pid_list
	TAKE_LOCK(&pid_mutex,"find_fds pid_mutex #2");
	if (get_list_size(&new_pid_list) != get_list_size(&pid_info.pid_list)) {
		// could be that we have only removed some processes from pid list,
		// in which case changed=0 when get here
		pid_info.changed = 1;
	}
	free_list(&pid_info.pid_list); pid_info.pid_list = new_pid_list;
	pthread_mutex_unlock(&pid_mutex);
		
	return pid_info.changed;
}

void find_escapees() {
	// this is called after refresh of pid_list, so pid list is up to date
	TAKE_LOCK(&pid_mutex,"find_escapees");
	for (size_t j=0; j< get_list_size(&pid_info.pid_list); j++) {
		conn_t c;
		memcpy(&c,get_list_item(&pid_info.pid_list, j),sizeof(conn_t));
		pthread_mutex_unlock(&pid_mutex);
		
		// is this a connection which ought to have been blocked (an "escapee") ?
		bl_item_t b;
		strlcpy(b.name, c.name,MAXCOMLEN);
		strlcpy(b.domain,c.domain,MAXDOMAINLEN);
		strlcpy(b.addr_name,c.dst_addr_name,INET6_ADDRSTRLEN);
		// get log entry for this item, if it exists.
		log_line_t *l = find_log_by_conn(c.name,&c.raw,0);
		if ( (((l!=NULL)&&(l->blocked!=0)) || (is_blocked(&b)!=0)) && (c.raw.udp==0)) {
			// its an active connection that is supposed to have been blocked
			TAKE_LOCK(&escapee_mutex,"find_fds escapee_mutex");
			int is_new_escapee = (!in_list(&pid_info.escapee_list,&c,0));
			pthread_mutex_unlock(&escapee_mutex);
			// we don't try to catch VPN conns, openvpn (at least) blocks RSTs-to-self
			int vpn = (pid_info.is_ppp)(c.raw.af, &c.raw.src_addr, &c.raw.dst_addr);
			//vpn=1; //disable catching
			int admissible = (l==NULL) || ((l!=NULL) && (l->escapee_count < MAX_ESCAPEE_ATTEMPTS));
			//printf("**is_new_escapee %d, vpn %d, admissible %d count %d\n",is_new_escapee,vpn,admissible,pid_info.escapee_thread_count);
			if (is_new_escapee && !vpn && admissible && (pid_info.escapee_thread_count<ESCAPEEMAX)) {
				conn_t *e = malloc(sizeof(conn_t));
				memcpy(e,&c,sizeof(conn_t));
				//printf("udp %d/%d\n",c.raw.udp,e->raw.udp);
				// get the initial seq number of conn from log, if possible.
				if (l==NULL) { // not in the log, conn started before app started up
					//INFO("escapee not in log %s(%d): %s:%u -> %s(%s):%u udp=%d,l=%d\n", c.name, c.pid, c.src_addr_name,c.raw.sport, c.domain, c.dst_addr_name, c.raw.dport, c.raw.udp,l==NULL);
					// guess ! the seq number is used to prompt local to send a pkt
					// when connection is idle so that we can get the real seq number
					// from it. its not needed for conns sending pkts already. this will
					// probably fail unless connection is already sending pkts
					e->raw.seq = (uint32_t)rand(); e->raw.ack = (uint32_t)rand();
					stats.escapees_not_in_log++;
					// add conn to log
					log_connection(&e->raw, &b, is_blocked(&b), 1.0, "", "", get_name_path(e->name));
					add_dns_conn(c.domain, c.name);
				} else { // in the log
					// we get the seq number from syn-ack in log ...
					e->raw.seq =l->raw.seq; e->raw.ack =l->raw.ack;
					struct timeval start; gettimeofday(&start, NULL);
					stats.num_escapees++;
					if (start.tv_sec - l->raw.ts.tv_sec > STALE_ESCAPEE_TIMEOUT) {
						// an ancient connection.  seq number is maybe too old now,
						// should we just choose a random one, or otherwise adjust it ?
						stats.stale_escapees++;
					}
					l->escapee_count++; // keep track of number of times we've tried to catch conn
					// if process name was unknown/unsure we can now update it in log,
					// and also update the blocked status
					double prev_conf = update_log_by_conn(c.name,&c.raw,is_blocked(&b));
					if ((prev_conf>0) && (prev_conf < 1.0-1.0e-6)) {
						// log entry was a guess, now that we're sure let's add
						// that new info to the dns_conn cache
						add_dns_conn(c.domain, c.name);
					}
				}
				// add new escapee to the active list ...
				TAKE_LOCK(&escapee_mutex,"find_fds escapee_mutex");
				add_item(&pid_info.escapee_list,&c,sizeof(conn_t));
				pthread_mutex_unlock(&escapee_mutex);
				INFO("escapee added %s(%d): %s:%u -> %s(%s):%u udp=%d,l=%d,vpn=%d\n", c.name, c.pid, c.src_addr_name,c.raw.sport, c.domain, c.dst_addr_name, c.raw.dport, c.raw.udp, l==NULL,vpn);
				
				// and ask helper to catch this "escapee" connection
				//pthread_t escapee_thread;
				//pthread_create(&escapee_thread,NULL,catch_escapee,e);
				(pid_info.start_catch_escapee)(e);
				cm_add_sample_lock(&stats.cm_escapee_thread_count,pid_info.escapee_thread_count);
				// escapee_thread will now remove from escapee_list and free(e)
			}
		}
		if (l!=NULL) free(l);
		TAKE_LOCK(&pid_mutex,"find_escapees #2");
	}
	pthread_mutex_unlock(&pid_mutex);
}

#include "helper.h"
void start_catch_escapee(conn_t *e) {
	pthread_t escapee_thread;
	pthread_create(&escapee_thread,NULL,catch_escapee,e);
}

void *catch_escapee(void *ptr) {
	TAKE_LOCK(&escapee_mutex,"catch_escapee");
	pid_info.escapee_thread_count++;
	pthread_mutex_unlock(&escapee_mutex);

	conn_t *e = (conn_t*)ptr;
	struct timeval start; gettimeofday(&start, NULL);

	//INFO("escapee started %s(%d) fd=%d %s:%u -> %s(%s):%u ack=%u,udp=%d\n", e->name, e->pid, e->fd,e->src_addr_name, e->raw.sport, e->domain, e->dst_addr_name, e->raw.dport, e->raw.ack,e->raw.udp);

	int c_sock;
	// block here if helper is busy with killing a connection
	if ( (c_sock=connect_to_helper(CATCHER_PORT,1))<0 ) {
		// either helper has gone away or listen queue for escapees is full.
		// if former, fatal error ?  just now we just muddle through, will
		// mean that don't catch escapees
		TAKE_LOCK(&escapee_mutex,"catch_escapee #2");
		pid_info.escapee_thread_count--;
		pthread_mutex_unlock(&escapee_mutex);
		return NULL;
	}
	//struct timeval end0; gettimeofday(&end0, NULL);
	//printf("catch escapee connected, %fs\n",(end0.tv_sec - start.tv_sec) +(end0.tv_usec - start.tv_usec)/1000000.0);

	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	ssize_t res;
	int vpn = is_ppp(e->raw.af, &e->raw.src_addr, &e->raw.dst_addr);
	if (vpn < 0) {WARN("escapee: interface down/gone away\n"); goto stop;}
	uint8_t vpn_bool = (vpn>0);
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	if ( (res=send(c_sock, &vpn_bool, sizeof(uint8_t),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->pid, sizeof(int),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.af, sizeof(int),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.dst_addr, sizeof(struct in6_addr),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.sport, sizeof(uint16_t),0) )<=0) goto err;
	if ( (res=send(c_sock, &e->raw.dport, sizeof(uint16_t),0) )<=0) goto err;
	// details in e are for an outgoing connection, so rst to self should echo back the
	// outgoing ack.  this ack is from a syn-ack so we need to add 1 to it
	if ( (res=send(c_sock, &e->raw.seq, sizeof(uint32_t),0) )<=0) goto err;
	//e->raw.ack++; // TEST, forces incorrect RST seq number to check RST probing works
	if ( (res=send(c_sock, &e->raw.ack, sizeof(uint32_t),0) )<=0) goto err;
	int8_t ok=0;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	// remove escapee from active list, will be re-added if conn still exists
	// next time find_fds() is called.
	struct timeval end; gettimeofday(&end, NULL);
	double t=(end.tv_sec - start.tv_sec) +(end.tv_usec - start.tv_usec)/1000000.0;
	char *result="";
	if (ok==1) {
		result="STOPPED";
		stats.escapees_hits++;
		cm_add_sample_lock(&stats.cm_t_escapees_hits,t);
	} else if (ok==-1) {
		result="NOT FOUND";
		stats.escapees_goneaway++;
	} else if (ok==0) { // failed to stop connection
		result = "FAILED to stop";
		uint32_t pkt_count, seq, ack;
		if (read(c_sock, &pkt_count, sizeof(uint32_t))<=0) goto err;
		if (pkt_count>0) {
			// if we sniffed pkts then get the seq/ack of last packet and
			// update log entry for this connection.  that way when next try
			// to stop the connection (since we failed this time) we'll
			// hopefully have better info.
			if (read(c_sock, &seq, sizeof(uint32_t))<=0) goto err;
			if (read(c_sock, &ack, sizeof(uint32_t))<=0) goto err;
			log_line_t *l = find_log_by_conn(e->name,&e->raw,0);
			l->raw.seq = seq; l->raw.ack = ack;
		}
		stats.escapees_misses++;
		cm_add_sample_lock(&stats.cm_t_escapees_misses,t);
	} else { //shouldn't happen
		result = "ERROR";
		ERR("Invalid helper response in catch_escapee()\n");
	}
	INFO("escapee %s(%d) fd=%d %s:%u -> %s(%s):%u ack=%u,udp=%d: %s. t=%fs\n", e->name, e->pid, e->fd,e->src_addr_name, e->raw.sport, e->domain, e->dst_addr_name, e->raw.dport, e->raw.ack,e->raw.udp,result,t);
	goto stop;
	
err:
	if (errno == EAGAIN) {
		INFO2("write escapee timeout\n");
		stats.escapee_timeouts++;
	} else {
		WARN("write escapee: %s\n", strerror(errno));
	}
stop:
	close(c_sock);
	TAKE_LOCK(&escapee_mutex,"catch_escapee #3");
	del_item(&pid_info.escapee_list,e);
	pid_info.escapee_thread_count--;
	pthread_mutex_unlock(&escapee_mutex);
	free(e);
	// refresh pid list and check for more escapees.
	// we also force a full refresh of pid list since even if fd hasn't
	// gone away just yet the associated cached fd state may/should
	// have changed.
	signal_pid_watcher(1,1);
	return NULL;
}


