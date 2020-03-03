//
//  helper.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "helper.h"

int connect_to_helper(int port, int quiet) {
	// open socket to helper process (that has priviledge to use raw socket)
	char err_msg[STR_SIZE];
	
	int sock=-1;
	if (!quiet) INFO("Trying to connect to appFirewall-Helper on port %d ... \n", port);
	int tries=0;
	while (tries < MAXTRIES) {
		DEBUG2("Try %d\n",tries);
		tries++;
		if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		//if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			ERR("socket: %s", strerror(errno));
			 // tell GUI to popup error to user
			snprintf(err_msg,STR_SIZE,"Problem connecting to appFirewall-Helper, socket: %s\n", strerror(errno));
			set_error_msg(err_msg,1);
			return -1;
		}
		struct sockaddr_un remote;
		remote.sun_family = AF_UNIX;
		snprintf(remote.sun_path, 104, "/var/run/appFirewall-Helper.%d",port);
		if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
			DEBUG2("Connecting to helper process on %s: %s\n", remote.sun_path, strerror(errno));
			if (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ECONNRESET) {
				// helper hasn't started yet, try again
				sleep(1);
				close(sock); // if don't close and reopen sock we get error
				continue;
			} else {
				// a more serious problem, bail.
				snprintf(err_msg,STR_SIZE,"Problem connecting to appFirewall-Helper on %s: %s\n", remote.sun_path, strerror(errno));
				set_error_msg(err_msg,1);
				return -1;
			}
		}
		break;
	}
	if (tries == MAXTRIES) {
		ERR("Failed to connect to appFirewall-Helper port %d after %d tries\n",port,tries);
		snprintf(err_msg,STR_SIZE,"Failed to connect to appFirewall-Helper port %d after %d tries\n",port,tries);
		set_error_msg(err_msg,1);
		return -1;
	}
	
	// try to speed up tcp
	int yes=1;
	setsockopt(sock,IPPROTO_TCP,TCP_NODELAY ,&yes,sizeof(yes));
	yes=1;
	setsockopt(sock,IPPROTO_TCP,TCP_SENDMOREACKS ,&yes,sizeof(yes));
	
	if (!quiet) INFO("connected to port %d.\n", port);
	return sock;
}

char* start_dnscrypt_proxy(const char* path) {
	// start dnscrypt-proxy service
	char* msg = NULL;
	static char msg_buf[STR_SIZE];

	printf("Asking helper to start dnscrypt-proxy.\n");
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,0))<0 ){
		return "Couldn't connect to helper";
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = StartDNScmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	size_t len = strlen(path);
	if ( (res=send(c_sock, &len, sizeof(size_t), 0) )<=0) goto err;
	if ( (res=send(c_sock, path, len, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0;
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	close(c_sock);
	if (ok != 1) {
		WARN("start_dnscrypt_proxy: command execution failed, return value %d\n",ok);
		snprintf(msg_buf,STR_SIZE, "helper command execution failed, return value %d\n",ok);
		msg = msg_buf;
	}
	return msg;
	
err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("start_dnscrypt_proxy timeout\n");
		msg = "Timeout when calling helper";
	} else {
		WARN("start_dnscrypt_proxy: %s\n", strerror(errno));
		snprintf(msg_buf,STR_SIZE,"helper socket error: %s",strerror(errno));
		msg = msg_buf;
	}
	return msg;
}

char* stop_dnscrypt_proxy() {	
	char* msg = NULL;
	static char msg_buf[STR_SIZE];

	printf("Asking helper to stop dnscrypt-proxy.\n");
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,0))<0 ){
		return "Couldn't connect to helper";
	}
	// stop dnscrypt-proxy service
	ssize_t res; int8_t ok=0;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = StopDNScmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	close(c_sock);
	if (ok != 1) {
		WARN("stop_dnscrypt_proxy: command execution failed, return value %d\n",ok);
		snprintf(msg_buf,STR_SIZE, "helper command execution failed, return value %d\n",ok);
		msg = msg_buf;
	}
	return msg;
	
err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("stop_dnscrypt_proxy timeout\n");
		msg = "Timeout when calling helper";
	} else {
		WARN("stop_dnscrypt_proxy: %s\n", strerror(errno));
		snprintf(msg_buf,STR_SIZE,"helper socket error: %s",strerror(errno));
		msg = msg_buf;
	}
	return msg;
}

static char line[STR_SIZE];
char* GetDNSOutput(int *dnscrypt_proxy_stopped, int *dnscrypt_proxy_running) {
	printf("Asking helper for last DNS line of output.\n");
	memset(line,0,STR_SIZE);
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,1))<0 ){
		return line;
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = GetDNSOutputcmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0, running=0; size_t len;
	if (read(c_sock, &len, sizeof(size_t))<=0) goto err; // wait here until helper is done
	if (len>0) {
		if (len>STR_SIZE-1) {WARN("GetDNSOutput length %zu too big\n",len); goto err;}
		if (read(c_sock, line, len)<=0) goto err;
	}
	if (read(c_sock, &running, 1)<=0) goto err;
	if (read(c_sock, &ok, 1)<=0) goto err;
	close(c_sock);
	*dnscrypt_proxy_stopped = ok;
	*dnscrypt_proxy_running = running;
	printf("DNS output dnscrypt_proxy_stopped/running=%d/%d, line=%s", ok, running, line);
	return line;

err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("unblock_QUIC timeout\n");
	} else {
		WARN("unblock_QUIC: %s\n", strerror(errno));
	}
	memset(line,0,STR_SIZE);
	return line;
}


char* block_QUIC() {
	char* msg = NULL;
	static char msg_buf[STR_SIZE];

	printf("Asking helper to block QUIC.\n");
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,0))<0 ){
		return "Couldn't connect to helper";
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = BlockQUICcmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0;
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	close(c_sock);
	if (ok != 1) {
		WARN("block_QUIC: command execution failed, return value %d\n",ok);
		snprintf(msg_buf,STR_SIZE, "helper command execution failed, return value %d\n",ok);
		msg = msg_buf;
	}
	return msg;

err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("block_QUIC timeout\n");
		msg = "Timeout when calling helper";
	} else {
		WARN("block_QUIC: %s\n", strerror(errno));
		snprintf(msg_buf,STR_SIZE,"helper socket error: %s",strerror(errno));
		msg = msg_buf;
	}
	return msg;
}

char* unblock_QUIC() {
	char* msg = NULL;
	static char msg_buf[STR_SIZE];

	printf("Asking helper to unblock QUIC.\n");
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,0))<0 ){
		return "Couldn't connect to helper";
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = UnblockQUICcmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0;
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	close(c_sock);
	if (ok != 1) {
		WARN("unblock_QUIC: command execution failed, return value %d\n",ok);
		snprintf(msg_buf,STR_SIZE, "helper command execution failed, return value %d\n",ok);
		msg = msg_buf;
	}
	return msg;

err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("unblock_QUIC timeout\n");
		msg = "Timeout when calling helper";
	} else {
		WARN("unblock_QUIC: %s\n", strerror(errno));
		snprintf(msg_buf,STR_SIZE,"helper socket error: %s",strerror(errno));
		msg = msg_buf;
	}
	return msg;
}

int QUIC_status() {
	printf("Asking helper for QUIC status.\n");
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,1))<0 ){
		return -1;
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	uint8_t cmd = QUICStatuscmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0;
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	close(c_sock);
	printf("QUIC status %d\n", ok);
	return ok;

err:
	close(c_sock);
	if (errno == EAGAIN) {
		WARN("unblock_QUIC timeout\n");
	} else {
		WARN("unblock_QUIC: %s\n", strerror(errno));
	}
	return -1;
}


char* helper_cmd_install(const char* src_dir, const char* dst_dir, const char* file) {
	char* msg = NULL;
	static char msg_buf[STR_SIZE];

	if (strcmp(file,"appFirewall.app"))
		return "Tried to call helper with invalid file";
	int c_sock=-1;
	if ( (c_sock=connect_to_helper(CMD_PORT,0))<0 ){
		return "Couldn't connect to helper";
	}
	ssize_t res;
	set_snd_timeout(c_sock, SND_TIMEOUT); // to be safe, will eventually timeout of send
	printf("helper_cmd_install src_dir=%s, dst_dir=%s\n",src_dir,dst_dir);
	uint8_t cmd = IntallUpdatecmd;
	if ( (res=send(c_sock, &cmd, 1, 0) )<=0) goto err;
	size_t len = strnlen(src_dir, STR_SIZE);
	if ( (res=send(c_sock, &len, sizeof(size_t), 0) )<=0) goto err;
	if ( (res=send(c_sock, src_dir, len, 0) )<=0) goto err;
	len = strnlen(dst_dir, STR_SIZE);
	if ( (res=send(c_sock, &len, sizeof(size_t), 0) )<=0) goto err;
	if ( (res=send(c_sock, dst_dir, len, 0) )<=0) goto err;
	set_recv_timeout(c_sock, RECV_TIMEOUT); // to be safe, read() will eventually timeout
	int8_t ok=0;
	if (read(c_sock, &ok, 1)<=0) goto err; // wait here until helper is done
	if (ok != 1) {
		WARN("helper_cmd_install: command execution failed, return value %d\n",ok);
		snprintf(msg_buf,STR_SIZE, "helper command execution failed, return value %d\n",ok);
		msg = msg_buf;
	}
	close(c_sock);
	return msg;

err:
	if (errno == EAGAIN) {
		WARN("helper_cmd_install timeout\n");
		msg = "Timeout when calling helper";
	} else {
		WARN("helper_cmd_install: %s\n", strerror(errno));
		snprintf(msg_buf,STR_SIZE,"helper socket error: %s",strerror(errno));
		msg = msg_buf;
	}
	close(c_sock);
	return msg;
}

void start_helper_listeners(int_sw dtrace, int_sw nstat) {
	// fire up thread that listens for pkts sent by helper
	
	if (get_unit_testing()) return; // don't start helpers when testing
	
	start_listener(); // pkt sniffer
	if (dtrace) start_dtrace_listener(); // dtrace
	//if (nstat) start_netstats();
}

void stop_helper_listeners() {
	stop_listener();
	stop_dtrace_listener();
}

