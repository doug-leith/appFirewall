//
//  util.c
//  com.leith.appFirewall-Helper
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

int readn(int fd, void* buf, int n) {
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

int bind_to_port(int port) {
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		ERR("Problem creating socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int yes=1;
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) == -1) {
		ERR("Setsockopt: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = inet_addr("127.0.0.1");;
	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
		ERR("Problem binding to localhost port %d: %s\n", port, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (listen(sock, 2) == -1) {
		ERR("Problem listening to localhost port %d: %s\n", port, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return sock;
}
