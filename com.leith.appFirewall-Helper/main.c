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

#define LOGFILE "/Library/Logs/appFirewall-Helper.log"
#define ROTFILE "/etc/newsyslog.d/appFirewall-Helper.conf"
// compile with gcc -g -lpcap -lnet pcap_sniffer.c dtrace.c util.c send_rst.c main.c
// and debug with lldb

void sigterm_handler(int signum) {
	INFO("signal %d received.\n", signum); // shouldn't really printf() in signal handler
	INFO("appFirewall-Helper exiting.\n");
	exit(EXIT_SUCCESS);
}

void sighup_handler(int signum) {
	// signalled by logrotate, reopen log file
	INFO("signal %d received, reloading logs.\n", signum);
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
		//exit(EXIT_FAILURE);
	}
	//int stdout_fd = dup(STDOUT_FILENO); // keep orig stdout
	if (!isatty(fileno(stdout))) {
		dup2(logfd,STDOUT_FILENO); // redirect stdout to log file
		dup2(logfd,STDERR_FILENO); // ditto stderr
		setbuf(stdout, NULL); // disable buffering on stdout
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
	sigaction(SIGPIPE, &action, NULL);

	// set up SIGTERM handler
	action.sa_handler = sigterm_handler;
	sigaction(SIGTERM, &action, NULL);

	// set up SIGHUP handler
	action.sa_handler = sighup_handler;
	sigaction(SIGHUP, &action, NULL);

	// configure log rotation
	// see https://www.freebsd.org/cgi/man.cgi?newsyslog.conf(5)
  char *rot_fmt="#logfilename\t\t\t[owner:group]\tmode\tcount\tsize(KB)\twhen\tflags\t[/pid_file\t[sig_num]\n%s\troot:wheel\t644\t5\t5000\t*\tNZ\n";
  char rot_str[1024];
  sprintf(rot_str,rot_fmt,LOGFILE);
	int rotatefd = open(ROTFILE,O_WRONLY|O_CREAT,0644);
	write(rotatefd,rot_str,strlen(rot_str));
	close(rotatefd);

	// now initialise libnet packet processing data structure
	//init_libnet();
	start_libnet();
	INFO("libnet started\n");
	
	start_listener();
	INFO("pcap listener started\n");

	start_dtrace();
	INFO("dtrace started\n");
	
	start_catcher_listener();
	INFO("catcher listener started\n");

	// once we get this far any errors are treated as non-fatal i.e.
	// won't kill process but instead will try to repair things
	
	// now wait in accept() loop to handle connections from GUI to send RST pkts
	rst_accept_loop();
}
