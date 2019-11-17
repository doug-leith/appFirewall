//
//  dtrace.c
//  com.leith.appFirewall-Helper
//


#include "dtrace.h"

// globals
static pthread_t dtrace_thread; // handle to dtrace thread
static int dtrace_pid=-1; // pid of forked process running dtrace cmd, used to kill it
static int d_sock=-1;
static int stdout_fd;

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

// Apple TCP control block: https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netinet/tcp_var.h.auto.html

// Note that dtrace script below can generate occasional errors e.g.
// error on enabled probe ID 5 (ID 971: syscall::connect_nocancel:return): invalid alignment (0x3356113e0009b1e) in action #1 at DIF offset 328
// this is a memory error and likely means that process has been killed between time
// connect call started and when it ended e.g. if laptop went to sleep and then
// awoke.  so hopefully no big deal since we don't care about killing such connections
// as they're already dying.
char* dtrace_script="\
-x quiet -x switchrate=100hz -n \
'\
syscall::connect*:entry{ \
connect_fd = arg0; \
} \
syscall::connect*:return{\
sock = ((struct socket *) (curproc->p_fd->fd_ofiles[connect_fd]->f_fglob->fg_data)); \
af2=sock->so_proto->pr_domain->dom_family; \
pcb = (struct inpcb *) sock->so_pcb; \
} \
syscall::connect*:return/af2==2/{ \
localPort = ntohs((uint16_t) pcb->inp_lport); \
remotePort = ntohs((uint16_t) pcb->inp_fport); \
l_addr= &pcb->inp_dependladdr.inp46_local.ia46_addr4.s_addr; \
r_addr = &pcb->inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr; \
localAddr = inet_ntoa((uint32_t*) l_addr); \
remoteAddr = inet_ntoa((uint32_t*) r_addr); \
printf(\"<appFirewall>,%s,%d,%d,%s,%d,%s,%d\\n\", execname, pid, af2, localAddr, localPort, remoteAddr, remotePort); \
} \
syscall::connect*:return/af2==30/{ \
localPort = ntohs((uint16_t) pcb->inp_lport); \
remotePort = ntohs((uint16_t) pcb->inp_fport); \
l6_addr= &pcb->inp_dependladdr.inp6_local; \
r6_addr = &pcb->inp_dependfaddr.inp6_foreign; \
localAddr = inet_ntoa6(l6_addr); \
remoteAddr = inet_ntoa6(r6_addr); \
printf(\"<appFirewall>,%s,%d,%d,%s,%d,%s,%d\\n\", execname, pid, af2, localAddr, localPort, remoteAddr, remotePort); \
} \
' ";

int exec(char* cmd, int *pipefd) {

	pid_t pid = fork();

	if (pid < 0)
		return pid; // erro
	else if (pid == 0) { // child
		// this is a bit messy.  we've already redirected stdout
		// to the logfile but have kept a copy of its file descriptor
		// in stdout_fd.  now that we're in forked child we (i) re-attach
		// stdout back to stdout_fd, then (ii) redirect stdout to
		// the pipe fd.  seems that both steps are necessary as dtrace
		// is writing to stdout FILE* using printf and we need to
		// make that change.
		dup2(stdout_fd,STDOUT_FILENO); // redirect stdout
		dup2(pipefd[1],STDOUT_FILENO); // redirect stdout to file
		//dup2(fd,STDERR_FILENO); // leave stderr alone though
		close(pipefd[1]); close(pipefd[0]);
		setbuf(stdout, NULL); // disable buffering on stdout

		int tries=0;
		for (;;) {
			execl("/bin/sh", "sh", "-c", cmd, NULL);
			// shouldn't happen. only returns here on an error
			ERR("dtrace tries %d: %s\n", tries, strerror(errno));
			tries++;
			if (tries>3) break;
		}
		exit(1);
	}
	return pid;

}

void kill_dtrace() {
	// and wait for it to finish cleanly
	if (dtrace_pid>0) {
		kill(dtrace_pid,SIGTERM);
		int status;
		int res=waitpid(dtrace_pid, &status, 0);
		INFO("dtrace stopped. res=%d exit:%d/signal:%d/stopped:%d\n",res, WIFEXITED(status),WIFSIGNALED(status),WIFSTOPPED(status));
		dtrace_pid = -1;
	} else {
		WARN("kill_trace() pid=%d\n",dtrace_pid);
	}
}

void *dtrace(void *ptr) {
	// wait in accept() loop to handle connections from GUI to receive dtrace info

	int pipefd[2];
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	int d_sock2;
	
	// assemble dtrace command
	char* cmd = "/usr/sbin/dtrace ";
	int slen = (int)(strlen(dtrace_script) + strlen(cmd));
	char *dtrace_cmd = malloc(slen+2);
	INFO("Starting dtrace ...\n");
	strlcpy(dtrace_cmd,cmd,slen);
	strlcat(dtrace_cmd,dtrace_script,slen);

	// now start the accept() loop
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d ...\n", DTRACE_PORT);
		if ((d_sock2 = accept(d_sock, (struct sockaddr *)&remote, &len)) <= 0) {
			ERR("Problem accepting new connection on localhost port %d: %s\n", DTRACE_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d\n", DTRACE_PORT);
		
		// open pipe for receiving dtrace output
		int res = pipe(pipefd);
		//pipefd[0] refers to the read end of the pipe. pipefd[1] refers to the write end of the pipe. Data written to the write end of the pipe is buffered by the kernel until it is read from the read end of the pipe
		
		INFO("Starting dtrace ...\n");
		// start a new process to execute dtrace
		dtrace_pid = exec(dtrace_cmd,pipefd);
		if (dtrace_pid <= 0) {
			ERR("Problem starting dtrace, pid=%d: %s\n", dtrace_pid,strerror(errno));
			close(d_sock2);
			continue;
		}
		close(pipefd[1]); // we don't use write end of pipe
		// fp receives dtrace output. we now sit here, read it and pass it
		// on to GUI client
		size_t inbuf_used = 0;
		char inbuf[LINEBUF_SIZE], line[LINEBUF_SIZE];
		for (;;) {
			if (read_line(pipefd[0], inbuf, &inbuf_used, line) <0) break; // problem reading dtrace output
			INFO("line=%s",line);
			if (res<0) break; // problem reading dtrace output
			if (send(d_sock2, line, strlen(line), 0)<=0) break;
		}
		INFO("Connection on port %d ended: %s\n", DTRACE_PORT, strerror(errno));
		close(d_sock2); close(pipefd[0]);
		// stop dtrace
		kill_dtrace();
	}
	return NULL;
}

void start_dtrace(int stdout_fd2) {
	// start listening for commands to receive dtrace info
	d_sock = bind_to_port(DTRACE_PORT);
	INFO("Now listening on localhost port %d\n", DTRACE_PORT);

	stdout_fd = stdout_fd2;
	pthread_create(&dtrace_thread, NULL, dtrace, NULL);
}
