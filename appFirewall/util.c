
#include "util.h"
#include <string.h>

#define STR_SIZE 1024
static char error_msg[STR_SIZE];
static char data_path[STR_SIZE];

// swift interface
char* get_error_msg() {
	return error_msg;
}

void set_error_msg(char* msg) {
	strlcpy(error_msg,msg,STR_SIZE);
}

char* get_path() {
	return data_path;
}

void set_path(const char* path) {
	strlcpy(data_path,path,STR_SIZE);
}

int readn(int fd, void* buf, int n) {
 // read n bytes from socket fd
	int res=0, posn=0;;
	while (posn<n) {
		//printf("posn=%d,n=%d\n",posn,n);
		res = (int)recv(fd, buf+posn, n-res, 0);
		if (res <= 0) {
			//printf("res=%d\n",res);
			return res;
		}
		posn+=res;
	}
	//printf("return pos=%d\n", posn);
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
        return -1;
      }
      if (rv < 0) {
        if (errno == EAGAIN) {
           WARN("dtrace connection timeout\n");
        } else {
           ERR("dtrace connection error: %s\n",strerror(errno));
        }
        return -1;
      }
      *inbuf_used += rv;
    }
    line[i++] = inbuf[read_posn++]; // advance read position within buffer
    if (line[i-1]=='\n') break; // have hit a newline, stop
  }
  if (i==LINEBUF_SIZE) {
    ERR("dtrace line larger than %d.\n",LINEBUF_SIZE);
    return -1;
  }
  line[i]='\0'; // terminate line as string, makes for easier printing when debugging
  // shift buffer contents so next line starts at posn 0
  memmove(inbuf,inbuf+read_posn,*inbuf_used-read_posn);
  *inbuf_used -= read_posn;

  return i;
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

char *trimwhitespace(char *str) {
  char *end;

  // Trim leading space
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}


