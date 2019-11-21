//
//  helper.c
//  appFirewall
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "helper.h"

int connect_to_helper(int port) {
	// open socket to helper process (that has priviledge to use raw socket)
	char err_msg[1024];
	
	int sock=-1;
	INFO("Trying to connect to appFirewall-Helper on port %d ...\n", port);
	int tries=0;
	while (tries < MAXTRIES) {
		DEBUG2("Try %d\n",tries);
		tries++;
		if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		//if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			ERR("socket: %s", strerror(errno));
			 // tell GUI to popup error to user
			sprintf(err_msg,"Problem connecting to appFirewall-Helper, socket: %s", strerror(errno));
			set_error_msg(err_msg);
			return -1;
		}
		struct sockaddr_un remote;
		remote.sun_family = AF_UNIX;
		sprintf(remote.sun_path,"/var/run/appFirewall-Helper.%d",port);
		if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
			DEBUG2("Connecting to helper process on %s: %s\n", remote.sun_path, strerror(errno));
			if (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ECONNRESET) {
				// helper hasn't started yet, try again
				sleep(1);
				close(sock); // if don't close and reopen sock we get error
				continue;
			} else {
				// a more serious problem, bail.
				sprintf(err_msg,"Problem connecting to appFirewall-Helper on %s: %s\n", remote.sun_path, strerror(errno));
				set_error_msg(err_msg);
				return -1;
			}
		}
		/*struct sockaddr_in remote;
		memset(&remote,0,sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_port = htons(port);
		remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		//char buf[256];
		//printf("%s",inet_ntop(AF_INET,&remote.sin_addr.s_addr,buf,245));
		if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
			DEBUG2("Connecting to helper process on port %d: %s\n", port, strerror(errno));
			if (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ECONNRESET) {
				// helper hasn't started yet, try again
				sleep(1);
				close(sock); // if don't close and reopen sock we get error
				continue;
			} else {
				// a more serious problem, bail.
				sprintf(err_msg,"Problem connecting to appFirewall-Helper on port %d: %s\n", port, strerror(errno));
				set_error_msg(err_msg);
				return -1;
			}
		}*/
		break;
	}
	if (tries == MAXTRIES) {
		ERR("Failed to connect to appFirewall-Helper port %d after %d tries\n",port,tries);
		sprintf(err_msg,"Failed to connect to appFirewall-Helper port %d after %d tries\n",port,tries);
		set_error_msg(err_msg);
		return -1;
	}
	
	// try to speed up tcp
	int yes=1;
	setsockopt(sock,IPPROTO_TCP,TCP_NODELAY ,&yes,sizeof(yes));
	yes=1;
	setsockopt(sock,IPPROTO_TCP,TCP_SENDMOREACKS ,&yes,sizeof(yes));
	
	INFO("connected to port %d.\n", port);
	return sock;
}

void start_helper_listeners() {
	// fire up thread that listens for pkts sent by helper
	start_listener();
	start_dtrace_listener();
}

void stop_helper_listeners() {
	stop_listener();
	stop_dtrace_listener();
}
