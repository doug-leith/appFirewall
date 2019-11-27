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
			str[strlen(str)-1]=0; // remove "\n"
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
	int res=0, posn=0;;
	while (posn<n) {
		res = (int)recv(fd, buf+posn, n-res, 0);
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
		ERR("Problem creating socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	int yes=1;
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) == -1) {
		ERR("Setsockopt: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	sprintf(local.sun_path,"/var/run/appFirewall-Helper.%d",port);
	unlink(local.sun_path);
	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
		ERR("Problem binding to %s: %s\n", local.sun_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	chmod(local.sun_path, 0777);
	if (listen(sock, q) == -1) {
		ERR("Problem listening to %s: %s\n", local.sun_path, strerror(errno));
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
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
}

inline void set_snd_timeout(int sockfd, int timeout) {
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
}

