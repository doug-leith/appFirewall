//
//  dtrace.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.

#include "dtrace.h"

// globals
static pthread_t dtrace_thread; // handle to dtrace thread
static pthread_cond_t dtrace_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dtrace_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
static int wakeup = 0;
static int dtrace_init_firsttime=1;

static int d_sock=-1, d_sock2=-1;
static int pid=-1;
static dtrace_hdl_t *g_dtp;
static dtrace_proginfo_t info;
static dtrace_prog_t *prog;

/*
source for struct inpcb:
	https://opensource.apple.com/source/xnu/xnu-1699.24.8/bsd/netinet/in_pcb.h.auto.html
source for struct in_addr_4in6:
	https://github.com/apple/darwin-xnu/blob/master/bsd/netinet/in_pcb.h
	struct in_addr_4in6 {
			u_int32_t       ia46_pad32[3];
			struct  in_addr ia46_addr4;
	};
source for tcp protocol block:
	https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netinet/tcp_var.h.auto.html
source for p_fd:
	https://opensource.apple.com/source/xnu/xnu-3789.1.32/bsd/kern/kern_descrip.c.auto.html
source for struct proc:
	https://github.com/apple/darwin-xnu/blob/master/bsd/sys/proc_internal.h
source for struct filedesc
https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/sys/filedesc.h.auto.html
*/

/* dtrace docs:
http://dtrace.org/guide/chp-fmt.html
http://dtrace.org/guide/chp-actsub.html
http://www.brendangregg.com/dtracetoolkit.html
http://www.brendangregg.com/dtrace.html#OneLiners
https://docs.oracle.com/cd/E18752_01/html/819-5488/gcgkk.html
https://docs.oracle.com/en/operating-systems/oracle-linux/6/adminsg/ol_examples_dtrace.html
https://gist.github.com/amitu/2134968 // for apple, v useful !
*/

// nb: important to use local vars (this->) here as multiple threads in kernel
//#define	AF_UNSPEC	0		/* unspecified */
//#define	AF_UNIX		1		/* local to host (pipes) */
//#define	AF_INET		2		/* internetwork: UDP, TCP, etc. */
//#define	AF_INET6	30		/* IPv6 */
/*
 typedef struct sa_endpoints {\
				 unsigned int     sae_srcif;      \
				 struct sockaddr *sae_srcaddr;    \
				 socklen_t        sae_srcaddrlen; \
				 struct sockaddr *sae_dstaddr;    \
				 socklen_t        sae_dstaddrlen; \
 }sa_endpoints_t; \

 syscall::connect:entry{ \
 printf(\"syscall connect entry %s\\n\",execname); \
 this->connect_fd = arg0; \
 this->len = arg2; \
 this->arg1 = copyin(arg1, this->len); \
 this->af0 = ((struct sockaddr*)this->arg1)->sa_family; \
 } \
 \
 syscall::connect_nocancel:entry{ \
 printf(\"syscall connect_nocancel entry %s\\n\",execname); \
 this->connect_fd = arg0; \
 this->len = arg2; \
 this->arg1 = copyin(arg1, this->len); \
 this->af0 = ((struct sockaddr*)this->arg1)->sa_family; \
 } \
 \
 syscall::connectx*:entry{ \
	 printf(\"syscall connectx entry %s\\n\",execname); \
	 this->af0=-1;\
	 this->connect_fd = arg0; \
	 this->arg1 = copyin(arg1, sizeof(struct sa_endpoints)); \
	 s = (uint8_t*)this->arg1; \
	 this->sa = (struct sa_endpoints*)this->arg1; \
	 printf(\"%s:%s %d %d %d %d %d %d %d %d %s\\n\",execname,probefunc, s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],stringof(this->arg1)); \
	 a=(struct sockaddr_in*)this->sa->sae_dstaddr; \
	 this->remotePort = ntohs((uint16_t) a->sin_port); \
	 this->remoteAddr = inet_ntoa((uint32_t*)&a->sin_addr); \
	 printf(\"%s %d %d %s (%d)\\n\",execname,a->sin_family,this->remotePort, this->remoteAddr, this->len); \
 }\
 \
 syscall::connect*:entry/this->af0==1/{ \
	 this->su = (struct sockaddr_un*)copyin(arg1, this->len); \
	 printf(\"%s:%s %s (%d)\\n\",execname,probefunc,this->su->sun_path, this->len);\
 }\
 \
 syscall::connect*:entry/this->af0==2/{ \
	 this->s4 = (struct sockaddr_in*)copyin(arg1, this->len); \
	 this->remotePort = ntohs((uint16_t) this->s4->sin_port); \
	 this->remoteAddr = inet_ntoa((uint32_t*)&this->s4->sin_addr); \
	 printf(\"%s:%s %d %d %s (%d)\\n\",execname,probefunc,this->s4->sin_family,this->remotePort, this->remoteAddr, this->len); \
 }\
 \
 syscall::connect*:entry/this->af0==30/{ \
	 this->s6 = (struct sockaddr_in6*)copyin(arg1, this->len); \
	 this->remotePort6 = ntohs((uint16_t) this->s6->sin6_port); \
	 this->remoteAddr6 =  inet_ntoa6(&this->s6->sin6_addr); \
	 printf(\"%s %d %d %s (%d)\\n\",execname,this->s6->sin6_family,this->remotePort6, this->remoteAddr6, this->len); \
 }\
 */
 /*
 syscall::connect*:return{\
	 this->last = curproc->p_fd->fd_nfiles; \
	 this->af2 = 0; \
	 this->fdptr = NULL; \
 } \
 syscall::connect*:return/this->connect_fd < this->last/{\
	 this->fdptr = curproc->p_fd->fd_ofiles[this->connect_fd]; \
 } \
 */
char* dtrace_script2="\
this struct fileproc* fdptr; \
syscall::connect*:entry{ \
  this->connect_fd = arg0; \
} \
syscall::connect*:return{\
  this->last = curproc->p_fd->fd_nfiles; \
  this->af2 = 0; \
  this->fdptr = curproc->p_fd->fd_ofiles[this->connect_fd]; \
} \
syscall::connect*:return/!this->fdptr/{\
  printf(\"%s bad file descriptor %d/%d for %s %d, ret=%d. likely mDNSResponder issue.\\n\", probefunc, this->connect_fd, this->last, execname, pid, arg1) \
} \
syscall::connect*:return/this->fdptr/{\
  this->sock = ((struct socket *) (this->fdptr->f_fglob->fg_data)); \
  this->af2=this->sock->so_proto->pr_domain->dom_family; \
  this->pcb = (struct inpcb *) this->sock->so_pcb; \
} \
syscall::connect*:return/this->af2==2/{ \
  this->localPort = ntohs((uint16_t) this->pcb->inp_lport); \
  this->remotePort = ntohs((uint16_t) this->pcb->inp_fport); \
  this->l_addr= &this->pcb->inp_dependladdr.inp46_local.ia46_addr4.s_addr; \
  this->r_addr = &this->pcb->inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr; \
  this->localAddr = inet_ntoa((uint32_t*) this->l_addr); \
  this->remoteAddr = inet_ntoa((uint32_t*) this->r_addr); \
  printf(\"<appFirewall>,%s,%d,%d,%s,%d,%s,%d,%s,%s\\n\", execname, pid, this->af2, this->localAddr, this->localPort, this->remoteAddr, this->remotePort,probefunc,probename); \
} \
syscall::connect*:return/this->af2==30/{ \
  this->localPort = ntohs((uint16_t) this->pcb->inp_lport); \
  this->remotePort = ntohs((uint16_t) this->pcb->inp_fport); \
  this->l6_addr= &this->pcb->inp_dependladdr.inp6_local; \
  this->r6_addr = &this->pcb->inp_dependfaddr.inp6_foreign; \
  this->localAddr = inet_ntoa6(this->l6_addr); \
  this->remoteAddr = inet_ntoa6(this->r6_addr); \
  printf(\"<appFirewall>,%s,%d,%d,%s,%d,%s,%d,%s,%s\\n\", execname, pid, this->af2, this->localAddr, this->localPort, this->remoteAddr, this->remotePort,probefunc,probename); \
} \
";

static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
	//printf("chewrec\n");
	if (rec == NULL) {
		return (DTRACE_CONSUME_NEXT);
	}
	dtrace_actkind_t act = rec->dtrd_action;
	if (act == DTRACEACT_EXIT) {
		return (DTRACE_CONSUME_NEXT);
	}
	return (DTRACE_CONSUME_THIS);
}

static int
chew(const dtrace_probedata_t *data, void *arg){
	//printf("chew\n");
	return (DTRACE_CONSUME_THIS);
}

int dtrace_dropped(const dtrace_dropdata_t *dropdata, void *arg) {
	printf("dtrace dropped %llu (total drops %llu): %s\n", dropdata->dtdda_drops, dropdata->dtdda_total,dropdata->dtdda_msg);
	return (DTRACE_HANDLE_OK);
}

int dtrace_buffered(const dtrace_bufdata_t *bufdata, void *arg){
	// get dtrace output and pass on to client
	//printf("dtrace_buffered\n");
	
	// before sending data, we recheck client when PID changes
	int current_pid = get_sock_pid(d_sock2, DTRACE_PORT);
	if (current_pid != pid) {
		if (check_signature(d_sock2, DTRACE_PORT)<0) {
			return (DTRACE_HANDLE_ABORT);
		}
	}
	pid = current_pid;
	
	const char* line = bufdata->dtbda_buffered;
	ssize_t res=-1;
	if (d_sock2 < 0) { // shouldn't happen
		printf("Dtrace_buffered() dsock2 %d\n", d_sock2);
	} else if ((res=send(d_sock2, line, strlen(line), 0))<strlen(line)) {
		// likely client closed their end of connection
		WARN("Dtrace send problem: %s\n",strerror(errno));
		return (DTRACE_HANDLE_ABORT);
	}
	printf("dt(res=%zd/%zd), %s",res,strlen(line),line);
	return (DTRACE_HANDLE_OK);
}

int init_dtrace() {
	int err;
	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		WARN("Failed to initialize dtrace: %s\n", dtrace_errmsg(NULL, err));
		return -1;
	}
	int flag = DTRACE_C_PSPEC;
	if (dtrace_init_firsttime) {
		//flag |= DTRACE_C_DIFV; // dump out dtrace code to help with debugging
		dtrace_init_firsttime=0;
	}
	if ((prog = dtrace_program_strcompile(g_dtp, dtrace_script2, DTRACE_PROBESPEC_NAME, flag, 0, NULL)) == NULL) {
		WARN("Dtrace: invalid probe specifier %s: %s\n",dtrace_script2, dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return -1;
	}
	if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
		WARN("Dtrace: failed to enable probes: %s\n",dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return -1;
	}
	if (dtrace_handle_buffered(g_dtp, dtrace_buffered, NULL) == -1) {
		WARN("Dtrace: unable to add buffered output: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return -1;
	}
	if (dtrace_handle_drop(g_dtp, dtrace_dropped, NULL) == -1) {
		WARN("Dtrace: unable to add drop handler: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	}
	dtrace_setopt(g_dtp, "bufsize", "4m");
	dtrace_setopt(g_dtp, "aggsize", "4m");
	dtrace_setopt(g_dtp, "temporal", "yes");
	dtrace_setopt(g_dtp, "stacksymbols", "enabled");
	dtrace_setopt(g_dtp, "quiet", 0);
	dtrace_setopt(g_dtp, "switchrate", "200hz");
	if (dtrace_go(g_dtp) != 0) {
			WARN("Dtrace: could not enable tracing %s\n",dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
			return -1;
	}
	return 0;
}

void signal_dtrace() {
	// called when sniff a SYN
	pthread_mutex_lock(&dtrace_mutex);
	wakeup = 1;
	pthread_cond_signal(&dtrace_cond);
	pthread_mutex_unlock(&dtrace_mutex);
}

void *dtrace(void *ptr) {
	// wait in accept() loop to handle connections from GUI to receive dtrace info

	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	
	// now start the accept() loop
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d (dtrace) ...\n", DTRACE_PORT);
		if ((d_sock2 = accept(d_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			WARN("Problem accepting new connection on localhost port %d (dtrace): %s\n", DTRACE_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d (dtrace)\n", DTRACE_PORT);
		if (check_signature(d_sock2, DTRACE_PORT)<0) {
			// couldn't authenticate client
			close(d_sock2); d_sock2=-1;
			continue;
		}
		pid = get_sock_pid(d_sock2, DTRACE_PORT);
		
		// open pipe for receiving dtrace output
		INFO("Starting dtrace ...\n");
		if (init_dtrace()<0) {
			dtrace_stop(g_dtp); dtrace_close(g_dtp);
			close(d_sock2); d_sock2=-1;
			continue;
		}

		//we now sit here and pass dtrace output back to GUI client
		set_snd_timeout(d_sock2, SND_TIMEOUT); // to be safe, send() will eventually timeout
		struct timespec t;
		for(;;) {
			// release mutex and wait
			clock_gettime(CLOCK_REALTIME, &t);
			t.tv_sec += 1;
			pthread_mutex_lock(&dtrace_mutex);
			int res = 0;
			while ((wakeup==0) && (res != ETIMEDOUT)) {
				dtrace_sleep(g_dtp);
				res = pthread_cond_timedwait(&dtrace_cond, &dtrace_mutex, &t);
				//res = pthread_cond_wait(&dtrace_cond, &dtrace_mutex);
				if ((res!=0) && (res!=ETIMEDOUT)) { // shouldn't happen
					WARN("Dtrace cond error: %s", strerror(errno));
				}
			}
			//printf("wake up\n");
			wakeup = 0;
			pthread_mutex_unlock(&dtrace_mutex);
			
			res = dtrace_work(g_dtp, NULL, chew, chewrec, NULL);
			if (res == DTRACE_WORKSTATUS_OKAY) {
				continue;
			}
			if (res == DTRACE_WORKSTATUS_DONE) break;
			int err;
			if ((err=dtrace_errno(g_dtp)) != EINTR) {
				WARN("Dtrace problem, stopping: %s\n",dtrace_errmsg(NULL, err));
				break;
			}
		}
		INFO("Connection on port %d (dtrace) ended: %s\n", DTRACE_PORT, strerror(errno));
		close(d_sock2); d_sock2=-1;
		// stop dtrace
		dtrace_stop(g_dtp); dtrace_close(g_dtp);
	}
	return NULL;
}

int dtrace_active() {
	return (d_sock2!=-1);
}

void start_dtrace() {
	// start listening for commands to receive dtrace info
	d_sock = bind_to_port(DTRACE_PORT,2);
	INFO("Now listening on localhost port %d\n", DTRACE_PORT);

	pthread_create(&dtrace_thread, NULL, dtrace, NULL);
}
