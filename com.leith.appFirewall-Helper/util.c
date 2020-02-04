//
//  util.c
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "util.h"

char* now(char* buf) {
	// returns string with current time
	time_t t;
	time(&t);
	struct tm result;
	struct tm * res = localtime_r(&t,&result);
	if (res!=NULL) {
		char* str=asctime_r(res,buf);
		if (str != NULL) {
			str[strnlen(str,1024)-1]=0; // remove "\n"
			return str;
		} else {
			return NULL;
		}
	} else {
	return NULL;
	}
}

ssize_t readn(int fd, void* buf, ssize_t n) {
 // read n bytes from socket fd
	ssize_t res=0, posn=0;;
	while (posn<n) {
		res = recv(fd, buf+posn, n-res, 0);
		if (res <= 0) {
			return res;
		}
		posn+=res;
	}
	return posn;
}


int read_line(int fd, char* inbuf, size_t *inbuf_used, char* line) {
  //read from socket until hit next newline. fine for both TCP and UDP sockets.
  int i=0;
  size_t read_posn=0;
  while (i < LINEBUF_SIZE) {
    if (read_posn == *inbuf_used) {
      // read from socket
      // TO DO: check that packet is from expected source IP/port (might be interleaved with a new request for example)
      ssize_t rv = read(fd, (void*)&inbuf[*inbuf_used], LINEBUF_SIZE - *inbuf_used);
      if (rv == 0) {
        WARN("dtrace connection closed.\n");
        line[i]='\0';
        return -1;
      }
      if (rv < 0) {
        if (errno == EAGAIN) {
           WARN("dtrace connection timeout\n");
        } else {
           ERR("dtrace connection error: %s\n",strerror(errno));
        }
        line[i]='\0';
        return -1;
      }
      *inbuf_used += rv;
    }
    line[i++] = inbuf[read_posn++]; // advance read position within buffer
    if (line[i-1]=='\n') break; // have hit a newline, stop
  }
  if (i==LINEBUF_SIZE) {
    ERR("dtrace line larger than %d.\n",LINEBUF_SIZE);
    line[i-1]='\0';
    return -1;
  }
  line[i]='\0'; // terminate line as string, makes for easier printing when debugging
  // shift buffer contents so next line starts at posn 0
  memmove(inbuf,inbuf+read_posn,*inbuf_used-read_posn);
  *inbuf_used -= read_posn;

  return i;
}

int bind_to_port(int port, int q) {
	int sock;
	//if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ERR("Problem creating socket, fatal: %s\n", strerror(errno));
		// this is serious as it means we can't talk with GUI client, bail.
		exit(EXIT_FAILURE);
	}
	
	int yes=1;
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) == -1) {
		WARN("Problem setting SO_REUSEADDR socket option: %s\n", strerror(errno));
		//exit(EXIT_FAILURE); // not great, but not fatal.
	}
	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	snprintf(local.sun_path, 104, "/var/run/appFirewall-Helper.%d",port);
	unlink(local.sun_path);
	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
		ERR("Problem binding to %s, fatal: %s\n", local.sun_path, strerror(errno));
		// this is serious as it means we can't talk with GUI client, bail.
		exit(EXIT_FAILURE);
	}
	if (chmod(local.sun_path, 0777)<0) WARN("Problem calling chmod on port %d, appFirewall might have trouble reading/writing socket to helper: %s", port, strerror(errno));
	if (listen(sock, q) == -1) {
		ERR("Problem listening to %s, fatal: %s\n", local.sun_path, strerror(errno));
		// this is serious as it means we can't talk with GUI client, bail.
		exit(EXIT_FAILURE);
	}
	return sock;
}

inline int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2) {
	if (af==AF_INET) { // IPv4
		uint32_t _addr1 = ((struct in_addr*)addr1)->s_addr;
		uint32_t _addr2 = ((struct in_addr*)addr2)->s_addr;
		return (_addr1==_addr2);
	} else { // IPv6
		return (memcmp(&addr1->s6_addr, &addr2->s6_addr, 16)==0);
	}
}

inline void set_recv_timeout(int sockfd, int timeout) {
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv)<0) {
		WARN("Problem setting SO_RCVTIMEO socket option: %s\n", strerror(errno));
	}
}

inline void set_snd_timeout(int sockfd, int timeout) {
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv)<0) {
		WARN("Problem setting SO_SNDTIMEO socket option: %s\n", strerror(errno));
	}
}

//#define NSEC_PER_SEC 1000000000
struct timespec timespec_normalise(struct timespec ts) {
	int count=0, max=1024;
	while((ts.tv_nsec >= NSEC_PER_SEC)&&(count<max)) {
		++(ts.tv_sec);
		ts.tv_nsec -= NSEC_PER_SEC;
		count++;
	}
	count=0;
	while((ts.tv_nsec <= -NSEC_PER_SEC)&&(count<max)) {
		--(ts.tv_sec);
		ts.tv_nsec += NSEC_PER_SEC;
		count++;
	}
	if(ts.tv_nsec < 0 && ts.tv_sec > 0) {
		--(ts.tv_sec);
		ts.tv_nsec = NSEC_PER_SEC - (-1 * ts.tv_nsec);
	} else if(ts.tv_nsec > 0 && ts.tv_sec < 0) {
		++(ts.tv_sec);
		ts.tv_nsec = -NSEC_PER_SEC - (-1 * ts.tv_nsec);
	}
	return ts;
}

struct timespec timespec_add(struct timespec ts1, struct timespec ts2) {
	ts1 = timespec_normalise(ts1);
	ts2 = timespec_normalise(ts2);
	ts1.tv_sec  += ts2.tv_sec;
	ts1.tv_nsec += ts2.tv_nsec;
	return timespec_normalise(ts1);
}


char *trimwhitespace(char *str) {
  char *end;

  // Trim leading space, we cap trimming at 1024 to be safe
  int count=0;
  size_t max = strnlen(str,1024);
  while(isspace((unsigned char)*str) && (count<max)) {str++; count++;}

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strnlen(str,1024) - 1;
  count=0;
  while( (end > str) && isspace((unsigned char)*end) && (count<max)) {end--; count++;}

  // Write new null terminator character
  end[1] = '\0';

  return str;
}

FILE* run_cmd_pipe(char* cmd, char* arg, int *pid) {
	// a version of popen that gives is the process pid, so we
	// can interrupt execution by killing it
	int pipefd[2]; pipe(pipefd); //create a pipe
	*pid = fork(); //span a child process
	if (*pid == 0) {
	// child
	 close(pipefd[0]);
	 dup2(pipefd[1], STDOUT_FILENO);
	 dup2(pipefd[1], STDERR_FILENO);
	 execl(cmd, cmd, arg, (char*) NULL);
	}
	// parent
	close(pipefd[1]);
	return fdopen(pipefd[0], "r");
}

int readline_timed(char* buf, int len, FILE* fp, int t) {
	int fd = fileno(fp);
	if (fd<0) return -1;
	fd_set input_set; FD_ZERO(&input_set); FD_SET(fd, &input_set);
	struct timeval timeout;
	timeout.tv_sec = t; timeout.tv_usec = 0;
	memset(buf,0,len);
	int res=0, posn=0;
	while (posn<len){
		res=select(fd+1, &input_set, NULL, NULL, &timeout);
		if (res < 0) { // error
			if (errno == EINTR) continue;
			break;
		}
		if (res == 0) break; //timeout
		if ((buf[posn]=(char)fgetc(fp))==EOF) break;
		if (buf[posn]=='\n') break; //newline
		posn++;
		FD_ZERO(&input_set ); FD_SET(fd, &input_set);
	}
	//int eof = (buf[posn]==EOF);
	buf[posn]=0; // terminate string
	//printf("res=%d, posn=%d, eof=%d, buf=%s\n",res,posn,eof,buf);
	if (posn == len) return 1; // out of buffer space, but otherwise ok
	if (res == 0) {
		// timeout
		WARN("Timeout in readline_timed()\n");
		return -2;
	} else if (res < 0) {
		// error
		WARN("Problem in readline_timed(): %s\n", strerror(errno));
		return -1;
	} else
		return posn; // will be 0 if pure EOF
}

int run_cmd(char* cmd, int t) {
	FILE *out = popen(cmd,"r");
	if (out == NULL) return -1;
	char resp[STR_SIZE];
	int res = readline_timed(resp,STR_SIZE,out,t);
	if (res>0) {
		printf("Output from %s: %s\n", cmd, resp);
		pclose(out);
		return 1;
	} else if (res<0) {
		// an error
		pclose(out);
		return res;
	}
	pclose(out);
	return 0;
}
