//
//  cmd.c
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 18/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#include "cmd.h"

static int c_sock=-1;
static pthread_t cmd_thread, dns_thread;
static pthread_mutex_t dns_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
static int dnscrypt_proxy_running=0, dnscrypt_proxy_stopped=1;
static char dnscrypt_cmd[STR_SIZE], dnscrypt_arg[STR_SIZE];
static char dnscrypt_lastline[STR_SIZE]; // last line of output
static int dnscrypt_pid=-1;

int kill_dnscrypt() {
	// stop dnscrypt external process.  called by dnscrypt thread below
	// and also by SIGTERM handler with helper exits
	int res = 0;
	if (dnscrypt_pid>0) res = kill(dnscrypt_pid,SIGKILL);
	dnscrypt_pid = -1;
	return res;
}

void* dnscrypt(void* ptr) {
	// run dnscrypt service
	int interfaces_setup=0, error=0;
	FILE *out = run_cmd_pipe(dnscrypt_cmd,dnscrypt_arg,&dnscrypt_pid);
	char *resp=NULL; size_t llen = 0; ssize_t res=0;
	pthread_mutex_lock(&dns_mutex);
	while (dnscrypt_proxy_running) {
		pthread_mutex_unlock(&dns_mutex);
		res=getline(&resp, &llen, out);
		if (res == -1) {
			pthread_mutex_lock(&dns_mutex);
			if (errno==EINTR) continue; // interrupted by signal
			dnscrypt_proxy_running = 0;
			pthread_mutex_unlock(&dns_mutex);
			if (feof(out)) { // likely dnscrypt has exited
				WARN("Problem reading dnscrypt-proxy output: end of file\n");
			} else { // something else has gone wrong ?
				WARN("Problem reading dnscrypt-proxy output: %s\n",strerror(errno));
			}
			error = 1;
			break; // bail
		}
		printf("dnscrypt-proxy: %s",resp);
		// keep a copy of the most recent line with res>0, it'll contain
		// details of error that caused dnscrypt to quit
		pthread_mutex_lock(&dns_mutex);
		if (resp != NULL) strlcpy(dnscrypt_lastline,resp,STR_SIZE);
		pthread_mutex_unlock(&dns_mutex);
		if (!interfaces_setup) {
			// now that dns server is running and we have seen first line
			// of output from it, set interfaces to point to the server.
			// nb: the API used by set_dns_server() is slow and a bit flaky (prone
			// to hangs/timeouts), so we have a few tries before giving up
			int tries = 0;
			while (((res=set_dns_server("127.0.0.1"))==0) && (tries<5)){tries++;}
			if (res==0) {
				// failed to set interfaces to point to server, let's exit
				WARN("Problem setting interface DNS to point to dnscrypt-proxy server, stopping dnscrypt-proxy\n");
				pthread_mutex_lock(&dns_mutex);
				dnscrypt_proxy_running = 0;
				pthread_mutex_unlock(&dns_mutex);
				break; // bail
			} else {
				interfaces_setup = 1;
			}
		}
	}
	if (!error) {
		// planned exit, clear most recent line
		pthread_mutex_lock(&dns_mutex);
		memset(dnscrypt_lastline,0,STR_SIZE);
		pthread_mutex_unlock(&dns_mutex);
	}

	// reset interface DNS settings, else user DNS will fail completely
	// since dnscrypt has stopped.
	// NB: if set_dns_server() fails here then that's pretty bad news
	// but not sure what we can do to recover without user intervention
	int tries = 0;
	while ((set_dns_server("empty")==0) && (tries<5)){tries++;}

	// now make sure dnscrypt is dead
	if (kill_dnscrypt()!=0) {
		WARN("Problem killing dnscrypt-proxy on exit: %s\n",strerror(errno));
	}
	// tidy up
	fclose(out); free(resp);
	// and exit thread
	printf("Dnscrypt-proxy thread stopped.\n");
	// we keep dnscrypt_proxy_stopped=0 all the way to here, so as to prevent a race
	// between starting a new dnscrypt instance while the instance here
	// is still closing down (and, in particular, bound to port 53).
	// at this point dnscrypt instance is fully closed, so we can finally
	// set dnscrypt_proxy_stopped=1.
	pthread_mutex_lock(&dns_mutex);
	dnscrypt_proxy_stopped = 1;
	pthread_mutex_unlock(&dns_mutex);
	return NULL;
}

void stop_dnscrypt() {
	pthread_mutex_lock(&dns_mutex);
	if (!dnscrypt_proxy_stopped) {
		// there's a race here.  existing dnscrypt instance
		// might be stopping, but not yet stopped.  its harmless
		// to now tell it again here to stop.
		dnscrypt_proxy_running=0; // flag to thread that it should stop
		pthread_mutex_unlock(&dns_mutex);
		// interrupt getline() in dns_thread so it checks
		// dnscrypt_proxy_running flag
		pthread_kill(dns_thread, SIGUSR1);
		printf("stop dnscrypt-proxy signalled.\n");
	} else {
		pthread_mutex_unlock(&dns_mutex);
		printf("stop dnscrypt-proxy: not running.\n");
	}
}

int set_dns_server(char* dns) {
	// get list of network services
	FILE *out = popen("/usr/sbin/networksetup -listallnetworkservices","r");
	if (out==NULL) {
		WARN("Problem getting list of network services in set_dns_server(): %s\n", strerror(errno));
		pclose(out);
		return -3;
	}
	int count = 0, res = 0;
	int failedforsome=0, okforsome=0;
	char service[STR_SIZE], cmd_str[STR_SIZE];
	while ((res=readline_timed(service, STR_SIZE, out,CMD_TIMEOUT))>0) {
		count++;
		if (count==1) continue; // ignore first line of output
		char *tmp = trimwhitespace(service);
		// this command seems to hang intermittently, but run_cmd() times out
		snprintf(cmd_str,STR_SIZE,"/usr/sbin/networksetup setdnsservers \"%s\" \"%s\"",tmp,dns);
		printf("setting dns server for %s to %s\n",tmp,dns);
		int res2=0;
		if ( (res2=run_cmd(cmd_str,CMD_TIMEOUT))==-2) {
			// timedout, try again
			res2=run_cmd(cmd_str,CMD_TIMEOUT);
		}
		if (res2<0) {
			failedforsome++; // keep a log of the failure
		} else {
			okforsome++; // keep a log of success
		}
		// if this cmd fails, just continue to next network service
	}
	printf("set_dns_server() finished\n");
	pclose(out);
	return okforsome;
}

void update_intf_dns() {
	// when interfaces change then if using DoH we update the DNS settings
	// - this is called from refresh_sniffers_list() since it keeps
	// an eye on interface changes
	if (dnscrypt_proxy_running) {
		int tries = 0, res=0;
		while (((res=set_dns_server("127.0.0.1"))==0) && (tries<5)){tries++;}
		if (res==0) {
			// failed to set interfaces to point to DoH server
			WARN("Problem in set_intf_dns() setting interface DNS to point to dnscrypt-proxy server.  Stopping dnscrypt-proxy!\n");
			// this seems pretty bad, stop dnscrypt-proxy as otherwise
			// we'll be left in a messed up state (dnscrypt running but
			// interfaces incorrectly configured)
			stop_dnscrypt();
		}
	}
}

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
			uint8_t cmd; int8_t ok=0, running = 0;
			char src[STR_SIZE], dst[STR_SIZE], cmd_str[STR_SIZE];
			size_t src_len=0, dst_len=0;
			if ( (res=readn(s2, &cmd, 1) )<=0) break;
			set_snd_timeout(s2, SND_TIMEOUT); // to be safe, will eventually timeout of send
			switch (cmd) {
				case IntallUpdatecmd:
					// install update
					printf("Received install update command\n");
					if ( (res=readn(s2, &src_len, sizeof(size_t)) )<=0) break;
					if ((src_len<0) || (src_len>STR_SIZE)) break;
					memset(src,0,STR_SIZE);
					if ( (res=readn(s2, src, src_len) )<=0) break;
					if ( (res=readn(s2, &dst_len, sizeof(size_t)) )<=0) break;
					if ((dst_len<0) || (dst_len>STR_SIZE)) break;
					memset(dst,0,STR_SIZE);
					if ( (res=readn(s2, dst, dst_len) )<=0) break;
					printf("Received install update command parameters: src %s, dst %s\n",src,dst);
					
					// values passed in are the src and dst directories, so add filename
					// (use a fixed filename to add a bit of extra safety since running as root)
					strlcat(src,"/appFirewall.app",STR_SIZE);
					strlcat(dst,"/appFirewall.app",STR_SIZE);
					
					char *rm = "/bin/rm", *mv = "/bin/mv";
					// TO DO: change to use rename() syscall (avoiding call out to shell)
					snprintf(cmd_str,STR_SIZE,"%s -rf %s.bak",rm,dst);
					printf("install update do: %s\n",cmd_str);
					if ((res=run_cmd(cmd_str,LONG_CMD_TIMEOUT))!=0) {
						WARN("Problem executing command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						ok = -1;
						break; // not really fatal, but failure might be a symptom of something serious
					}
					// keep copy of existing app
					snprintf(cmd_str,STR_SIZE,"%s %s %s.bak",mv,dst,dst);
					printf("install update do: %s\n",cmd_str);
					if ((res=run_cmd(cmd_str,LONG_CMD_TIMEOUT))!=0) {
						WARN("Problem executing command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						ok = -2;
						break;
					}
					// install new app
					snprintf(cmd_str,STR_SIZE,"%s '%s' %s",mv,src,dst);
					printf("install update do: %s\n",cmd_str);
					if ((res=run_cmd(cmd_str,LONG_CMD_TIMEOUT))!=0) {
						WARN("Problem installing update using %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						// try to restore old app
						snprintf(cmd_str,STR_SIZE,"%s %s.bak %s",mv,dst,dst);
						run_cmd(cmd_str,LONG_CMD_TIMEOUT); // if this fails there's not much we can do to recover !
						ok = -3;
						break;
					}
					// successful install, tidy up
					snprintf(cmd_str,STR_SIZE,"%s -rf %s.bak",rm, dst);
					printf("install update do: %s\n",cmd_str);
					if ((res=run_cmd(cmd_str,LONG_CMD_TIMEOUT))!=0) {
						WARN("Problem removing backup with command %s: %s (res=%zd)", cmd_str, strerror(errno), res);
						// not fatal ?
					}
					printf("install update successful\n");
					ok = 1;
					break;
				case BlockQUICcmd:
					//sudo pfctl -a com.apple/appFirewall -s rules // list rules
					printf("Received block QUIC command\n");
					snprintf(cmd_str,STR_SIZE,"/bin/echo \"block drop quick proto udp from any to any port 443\" | /sbin/pfctl -a com.apple/appFirewall -f -");
					printf("block QUIC do: %s\n",cmd_str);
					if ((res=run_cmd(cmd_str,CMD_TIMEOUT)) != 0) {
						WARN("Problem blocking QUIC, res=%zd\n",res);
						break;
					}
					printf("Block QUIC command successful\n");
					ok = 1;
					break;
				case UnblockQUICcmd:
					printf("Received unblock QUIC command\n");
					if ((res=run_cmd("/sbin/pfctl -a com.apple/appFirewall -F rules", CMD_TIMEOUT)) != 0) {
						WARN("Problem unblocking QUIC, res=%zd\n",res);
						break;
					}
					printf("Unblock QUIC command successful\n");
					ok = 1;
					break;
				case QUICStatuscmd:
					ok = (int8_t)run_cmd("/sbin/pfctl -a com.apple/appFirewall -s rules 2>&1 | grep block", CMD_TIMEOUT);
					break;
				case StartDNScmd:
					printf("Received start dnscrypt-proxy command\n");
					if ( (res=readn(s2, &src_len, sizeof(size_t)) )<=0) break;
					if ((src_len<0) || (src_len>STR_SIZE)) break;
					memset(src,0,STR_SIZE);
					if ( (res=readn(s2, src, src_len) )<=0) break;
					snprintf(dnscrypt_cmd,STR_SIZE, "%s/Library/dnscrypt-proxy", src);
					// check signature of executable
					if (check_file_signature(dnscrypt_cmd,0)<0) {
						// code failed signature check, bail
						ok = -1;
						break;
					}
					snprintf(dnscrypt_arg,STR_SIZE, "-config=%s/Resources/dnscrypt-proxy.toml", src);
					printf("cmd=%s %s\n",dnscrypt_cmd, dnscrypt_arg);
					// its important to take a lock here so that we
					// avoid a race between starting a new dnscrypt instance
					// here while an old instance is still closing down.
					pthread_mutex_lock(&dns_mutex);
					if (dnscrypt_proxy_stopped) {
						dnscrypt_proxy_running = 1;
						dnscrypt_proxy_stopped = 0;
						pthread_mutex_unlock(&dns_mutex);
						pthread_create(&dns_thread, NULL, dnscrypt, NULL);
						pthread_detach(dns_thread); // so we don't need to join
						printf("start dnscrypt-proxy completed.\n");
					} else {
						// there's a race here.  if existing dnscrypt instance is
						// stopping (but not yet stopped) then dnscrypt_proxy_stopped=0
						// so we fall though to here and do nothing.  but if we came
						// back in a while the existing instance would be properly stopped.
						// seems unavoidable though since existing instance is
						// bound to port 53 (blocking it for new instance) until it stops.
						// we fail safe to doing nothing in this case.
						pthread_mutex_unlock(&dns_mutex);
						printf("start dnscrypt-proxy: already running\n");
					}
					ok=1;
					break;
				case StopDNScmd:
					printf("Received stop dnscrypt-proxy command\n");
					stop_dnscrypt();
					ok=1;
					break;
				case GetDNSOutputcmd:
					pthread_mutex_lock(&dns_mutex);
					strlcpy(src,dnscrypt_lastline,STR_SIZE);
					running = (int8_t)dnscrypt_proxy_running;
					ok = (int8_t)dnscrypt_proxy_stopped;
					pthread_mutex_unlock(&dns_mutex);
					src_len = strnlen(src,STR_SIZE);
					if (send(s2, &src_len, sizeof(size_t), 0)<=0) break;
					if (src_len>0) {
						if (send(s2,src, src_len, 0)<=0) break;
					}
					if (send(s2, &running, sizeof(int8_t), 0)<=0) break;
					break;
				default:
					WARN("Unexpected command received: %d\n", cmd);
					break; // close connection
			}
			// send response back
			if (send(s2, &ok, 1, 0)<=0) break;
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
