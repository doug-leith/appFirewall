
#include "util.h"

#define STR_SIZE 1024
static char error_msg[STR_SIZE];
static char data_path[STR_SIZE];

// stats
stats_t stats;

// loggin level
int verbose = 1;

void set_logging_level(int level) {
	verbose = level;
}

void print_stats() {
	INFO("dtrace hits %d/misses %d, pidinfo hits %d/misses %d, pidinfo_cache hits %d/misses %d, waitinglist hits %d/misses %d.  avg times: sniff %.2f, not blocked %.2f, blocked %.2f, dns %.2f, udp %.2f, waitinglist hits %.2f/misses %.2f, pidinfo cache %.2f\n",
	stats.dtrace_hits, stats.dtrace_misses,stats.pidinfo_hits, stats.pidinfo_misses,stats.pidinfo_cachehits, stats.pidinfo_cachemisses,
	stats.n_t_waitinglist_hits,stats.n_t_waitinglist_misses,
	stats.sum_t_sniff/stats.n_t_sniff*1000, stats.sum_t_notblocked/stats.n_t_notblocked*1000,
	stats.sum_t_blocked/stats.n_t_blocked*1000,
	stats.sum_t_dns/stats.n_t_dns*1000,
	stats.sum_t_udp/stats.n_t_udp*1000,
	stats.sum_t_waitinglist_hits/stats.n_t_waitinglist_hits*1000, stats.sum_t_waitinglist_misses/stats.n_t_waitinglist_misses*1000,
	stats.sum_t_pidinfo_cache/stats.n_t_pidinfo_cache*1000
	);
}

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

void redirect_stdout() {
	// set up logging
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,APPLOGFILE,STR_SIZE);
	int logfd = open(path,O_RDWR|O_CREAT|O_APPEND,0644);
	if (logfd == -1) {
		ERR("Failed to open %s: %s\n",path,strerror(errno));
		//exit(EXIT_FAILURE);
	}
	//if (!isatty(fileno(stdout))) {
		dup2(logfd,STDOUT_FILENO); // redirect stdout to log file
		dup2(logfd,STDERR_FILENO); // ditto stderr
		setbuf(stdout, NULL); // disable buffering on stdout
	//} else {
	//	INFO("logging to terminal\'n");
	//}
	close(logfd);
}

int robust_inet_pton(int *af, const char * restrict src, void * restrict dst) {
	int res=inet_pton(*af, src, dst);
	if (res==0) {
		// likely mismatch between af and address type
		// - definitely happens with matlab
		if (*af == AF_INET) {
			res=inet_pton(AF_INET6,src,dst);
			if (res==1) *af = AF_INET6;
		} else {
			res=inet_pton(AF_INET,src,dst);
			if (res==1) *af = AF_INET;
		}
	}
	return res;
}

const char* robust_inet_ntop(int *af, const void * restrict src, char * restrict dst, socklen_t size) {
	const char *res=inet_ntop(*af, src, dst, size);
	if (res==NULL) {
		// mismatch between af and address type?
		// - definitely happens with matlab
		if (*af == AF_INET) {
			res=inet_ntop(AF_INET6,src,dst,size);
			if (res!=NULL) *af = AF_INET6;
		} else {
			res=inet_ntop(AF_INET,src,dst,size);
			if (res!=NULL) *af = AF_INET;
		}
	}
	return res;
}
