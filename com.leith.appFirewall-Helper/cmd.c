//
//  cmd.c
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 18/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#include "cmd.h"

static int c_sock=-1;
static pthread_t cmd_thread; // handle to listener thread

void* cmd_accept_loop(void* ptr) {
	// now wait in accept() loop to handle connections from GUI to send do stuff
	ssize_t res=0;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	int s2;
	for(;;) {
		INFO("Waiting to accept connection on localhost port %d (send_rst)...\n", CMD_PORT);
		if ((s2 = accept(c_sock, (struct sockaddr *)&remote, &len)) == -1) {
			ERR("Problem accepting new connection on localhost port %d (send_rst): %s\n", CMD_PORT, strerror(errno));
			continue;
		}
		INFO("Started new connection on port %d (recv_cmd)\n", CMD_PORT);
		if (check_signature(s2, CMD_PORT)<0) {
			// couldn't authenticate client
			close(s2);
			continue;
		}
		int pid = get_sock_pid(s2, CMD_PORT);
		
		// when UI starts up it creates a connection and keeps it open
		// until it shuts down, so we accept and then keep listening
		// until other side closes (or we get an error).
		for(;;) {
			// before reading data, we recheck client when PID changes
			int current_pid = get_sock_pid(s2, CMD_PORT);
			if (current_pid != pid) {
				if (check_signature(s2, CMD_PORT)<0) break;
			}
			pid = current_pid;
			uint8_t cmd; int8_t ok=0;
			char src[STR_SIZE], dst[STR_SIZE], cmd_str[STR_SIZE];
			size_t src_len=0, dst_len=0;
			if ( (res=readn(s2, &cmd, 1) )<=0) break;
			switch (cmd) {
				case 1:
					// install update
					if ( (res=readn(s2, &src_len, sizeof(size_t)) )<=0) break;
					if ((src_len<0) || (src_len>STR_SIZE)) break;
					if ( (res=readn(s2, src, src_len) )<=0) break;
					if ( (res=readn(s2, &dst_len, sizeof(size_t)) )<=0) break;
					if ((dst_len<0) || (dst_len>STR_SIZE)) break;
					if ( (res=readn(s2, dst, dst_len) )<=0) break;
					// values passed in are the src and dst directories, so add filename
					// (use a fixed filename to add a bit of extra safety since running as root)
					strlcat(src,"appFirewall.app",STR_SIZE);
					strlcat(dst,"appFirewall.app",STR_SIZE);
					
					char *rm = "/bin/rm", *mv = "/bin/mv";
					snprintf(cmd_str,STR_SIZE,"%s -rf %s.bak",rm,dst);
					if ((res=system(cmd_str))!=0) {
						WARN("Problem executing command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						ok = -1;
						break; // not really fatal, but failure might be a symptom of something serious
					}
					// keep copy of existing app
					snprintf(cmd_str,STR_SIZE,"%s %s %s.bak",mv,dst,dst);
					if ((res=system(cmd_str))!=0) {
						WARN("Problem executing command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						ok = -2;
						break;
					}
					// install new app
					snprintf(cmd_str,STR_SIZE,"%s %s %s",mv,src,dst);
					if ((res=system(cmd_str))!=0) {
						WARN("Problem installing update using %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						// try to restore old app
						snprintf(cmd_str,STR_SIZE,"%s %s.bak %s",mv,dst,dst);
						system(cmd_str); // if this fails there's not much we can do to recover !
						ok = -3;
						break;
					}
					// successful install, tidy up
					snprintf(cmd_str,STR_SIZE,"%s -rf %s.bak",rm, dst);
					if ((res=system(cmd_str))!=0) {
						WARN("Problem removing backup with command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						// not fatal
					}
					ok = 1;
					break;
				default:
					WARN("Unexpected command received: %d\n", cmd);
					break; // close connection
			}
			// send response back
			set_snd_timeout(s2, SND_TIMEOUT); // to be safe, will eventually timeout of send
			if (send(s2, &ok, 1, 0)<0) break;
		}
		// likely UI client has closed its end of the connection, in which
		// case res=0, otherwise something worse has happened to connection
		if (res<0) WARN("recv() on port %d (recv_cmd): %s\n",CMD_PORT, strerror(errno));
		INFO("Connection closed on port %d (recv_cmd).\n", CMD_PORT);
		close(s2);
	}
}

void start_cmd() {
	// start listening for requests to do stuff
	c_sock = bind_to_port(CMD_PORT,2);
	INFO("Now listening on localhost port %d (%s)\n", CMD_PORT, "recv_cmd");
	pthread_create(&cmd_thread, NULL, cmd_accept_loop, NULL);
}
