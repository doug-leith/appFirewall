//
//  appFirewall-Helper
//	- raw socket handler for appFirewall, needs root privilege
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//
// SMJobBless() installs appFirewall-Helper to /Library/PrivilegedHelperTools/
// The steps to get SMJobBless() to work:
// 1. Helper's launch.plist must include label entry with identifier of this helper
//		i.e. com.leith.appFirewall-Helper
// 2. Helper's Info.plist must contain "Clients allowed to add and remove tool" entry
//    with main appFirewall app's identifier
// 3. Main appFirewall's Info.plist must contain "Tools owned after installation" entry
//    pointing to this helper app com.leith.appFirewall-Helper
// 4. And the secret/non-documented step:  add the following linker options to
//	 	com.leith.appFirewall-Helper:
//		-sectcreate __TEXT __info_plist com.leith.appFirewall-Helper/Info.plist
//		-sectcreate __TEXT __launchd_plist com.leith.appFirewall-Helper/launchd.plist
//		which embed the plist files into the com.leith.appFirewall-Helper executable
// 5. Last step: main appFirewall app must copy com.leith.appFirewall-Helper executable
//		to Contents/Library/LaunchServices folder within the app bundle
//
// See https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless

// TCP header details: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_timestamps
// libnet tutorials: https://repolinux.wordpress.com/2011/09/18/libnet-1-1-tutorial/#receiving-packets
//https://repolinux.wordpress.com/category/libnet/#sending-multiple-packets
// libnet source: https://github.com/libnet/libnet
// RFC on RST attack mitigations: https://tools.ietf.org/html/rfc5961#section-3.2

//source for tcp protocol block:
//https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netinet/tcp_var.h.auto.html

#include <stdio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include "util.h"
#include "pcap_sniffer.h"
#include "dtrace.h"
#include "send_rst.h"
#include "catch_escapee.h"
#include "cmd.h"

#define LOGFILE "/Library/Logs/appFirewall-Helper.log"
#define ROTFILE "/etc/newsyslog.d/appFirewall-Helper.conf"
#define PIDFILE "/var/run/com.leith.appFirewall-Helper.pid"
// compile with gcc -g -lpcap -lnet pcap_sniffer.c dtrace.c util.c send_rst.c main.c
// debug with lldb:
// sudo lldb ./com.leith.appFirewall-Helper
// env MallocStackLogging=1
// run
// and in a separate terminal run: leaks <pid>

void sigterm_handler(int signum) {
	INFO("signal %d (SIGTERM=%d) received.\n", signum, SIGTERM);
	INFO("appFirewall-Helper exiting.\n");
	stop_sniffer(); stop_catcher(); // release /dev/bpf
	exit(EXIT_SUCCESS);
}

void sighup_handler(int signum) {
	// signalled by logrotate, reopen log file
	INFO("signal %d (SIGHUP=%d) received, reloading logs.\n", signum, SIGHUP);
	int logfd = open(LOGFILE,O_RDWR|O_CREAT|O_APPEND,0644);
	dup2(logfd,STDOUT_FILENO); // redirect stdout to log file
	dup2(logfd,STDERR_FILENO); // ditto stderr
	setbuf(stdout, NULL); // disable buffering on stdout
	close(logfd);
}

int main(int argc, char *argv[]) {

	#pragma unused(argc)
	#pragma unused(argv)

	// set up logging
	int logfd = open(LOGFILE,O_RDWR|O_CREAT|O_APPEND,0644);
	if (logfd == -1) {
		ERR("Failed to open logfile: %s\n",strerror(errno));
	}
	//int stdout_fd = dup(STDOUT_FILENO); // keep orig stdout
	if (!isatty(fileno(stdout))) {
		if (logfd>0)  {
			if (dup2(logfd,STDOUT_FILENO)<0) WARN("Problem redirecting stdout to %s: %s",LOGFILE, strerror(errno)); // redirect stdout to log file
			if (dup2(logfd,STDERR_FILENO)<0) WARN("Problem redirecting stderr to %s: %s",LOGFILE, strerror(errno)); // ditto stderr
			setbuf(stdout, NULL); // disable buffering on stdout
		} else {
			// lack of log file is quite serious if don't have tty, should we exit ?
		}
	} else {
		INFO("logging to terminal\'n");
	}
	close(logfd);


	INFO("appFilter-Helper started.\n");
			
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;

	action.sa_handler = SIG_IGN;
	// disable SIGPIPE, we'll catch such errors ourselves
	if (sigaction(SIGPIPE, &action, NULL)<0) WARN("Problem setting SIGPIPE handler, communication with appFirewall GUI may fail: %s",strerror(errno));

	// set up SIGTERM handler
	action.sa_handler = sigterm_handler;
	if (sigaction(SIGTERM, &action, NULL)<0) WARN("Problem setting SIGTERM handler, its not serious though: %s",strerror(errno));

	// set up SIGHUP handler
	action.sa_handler = sighup_handler;
	if (sigaction(SIGHUP, &action, NULL)<0) WARN("Problem setting SIGHUP handler, log may not rotate properly: %s",strerror(errno));

	// configure log rotation
	// see https://www.freebsd.org/cgi/man.cgi?newsyslog.conf(5)
	int pid = getpid();
	int pidfd = open(PIDFILE,O_WRONLY|O_CREAT,0644);
	if (pidfd == -1) {
		WARN("Failed to open pid file %s, log may fail to rotate properly: %s\n",PIDFILE, strerror(errno));
	} else {
		char pid_str[STR_SIZE];
		snprintf(pid_str,STR_SIZE,"%d\n",pid);
		write(pidfd,pid_str,strnlen(pid_str,STR_SIZE));
		close(pidfd);
	}
	char *rot_fmt="#logfilename\t\t\t[owner:group]\tmode\tcount\tsize(KB)\twhen\tflags\t[/pid_file\t[sig_num]\n%s\troot:wheel\t644\t5\t5000\t*\tZ\t/var/run/com.leith.appFirewall-Helper.pid\n";
  char rot_str[STR_SIZE];
  snprintf(rot_str,STR_SIZE,rot_fmt,LOGFILE);
	int rotatefd = open(ROTFILE,O_WRONLY|O_CREAT,0644);
	if (rotatefd == -1) {
		WARN("Failed to open syslog config file %s, log will not be rotated: %s\n",ROTFILE, strerror(errno));
	} else {
		write(rotatefd,rot_str,strnlen(rot_str,STR_SIZE));
		close(rotatefd);
	}

	// now initialise libnet packet processing data structure
	//init_libnet();
	start_rst();
	INFO("rst started\n");
	
	start_listener();
	INFO("pcap listener started\n");

	start_dtrace();
	INFO("dtrace started\n");
	
	start_catcher_listener();
	INFO("catcher listener started\n");

	start_cmd();
	INFO("recv cmd started\n");
	
	// once we get this far any errors are treated as non-fatal i.e.
	// won't kill process but instead will try to repair things
	
	// flush DNS
	INFO("Flushing DNS (sending HUP to mDNSResponder) ...\n");
	run_cmd("/usr/bin/pkill -HUP mDNSResponder");
	
	INFO("Starting RST loop ...\n");
			
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	rst_accept_loop();
}
