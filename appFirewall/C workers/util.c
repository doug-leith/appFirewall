
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

void init_stats() {
	memset(&stats,0,sizeof(stats_t));
	double quants[] = {0.5, 0.90, 0.99};
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_notblocked);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_blocked);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_waitinglist_hit);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_waitinglist_miss);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_dns);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_pidinfo_cache_hit);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_pidinfo_cache_miss);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_sniff);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_udp);
}

void print_stats() {
	INFO("dtrace hits %d/misses %d, pidinfo hits %d/misses %d, pidinfo_cache hits %d/misses %d, waitinglist hits %d/misses %d, #escapees %d\ntiming 50th/90th percentiles: sniff %.2f/%.2f, not blocked %.2f/%.2f, blocked %.2f/%.2f, dns %.2f/%.2f, udp %.2f/%.2f, waitinglist hits %.2f/%.2f. waitinglist misses %.2f/%.2f, pidinfo cache hit %.2f/%.2f, pidinfo cache miss %.2f/%.2f\n",
	stats.dtrace_hits, stats.dtrace_misses,stats.pidinfo_hits, stats.pidinfo_misses,stats.pidinfo_cachehits, stats.pidinfo_cachemisses,
	stats.waitinglist_hits,stats.waitinglist_misses,
	stats.num_escapees,
	cm_query(&stats.cm_t_sniff,0.5)*1000, cm_query(&stats.cm_t_sniff,0.9)*1000,
	cm_query(&stats.cm_t_notblocked,0.5)*1000, cm_query(&stats.cm_t_notblocked,0.9)*1000,
	cm_query(&stats.cm_t_blocked,0.5)*1000, cm_query(&stats.cm_t_blocked,0.9)*1000,
	cm_query(&stats.cm_t_dns,0.5)*1000, cm_query(&stats.cm_t_dns,0.9)*1000,
	cm_query(&stats.cm_t_udp,0.5)*1000, cm_query(&stats.cm_t_udp,0.9)*1000,
	cm_query(&stats.cm_t_waitinglist_hit,0.5)*1000, cm_query(&stats.cm_t_waitinglist_hit,0.9)*1000,
	cm_query(&stats.cm_t_waitinglist_miss,0.5)*1000, cm_query(&stats.cm_t_waitinglist_miss,0.9)*1000,
	cm_query(&stats.cm_t_pidinfo_cache_hit,0.5)*1000, cm_query(&stats.cm_t_pidinfo_cache_hit,0.9)*1000,
	cm_query(&stats.cm_t_pidinfo_cache_miss,0.5)*1000, cm_query(&stats.cm_t_pidinfo_cache_miss,0.9)*1000
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

#define NSEC_PER_SEC 1000000000
struct timespec timespec_normalise(struct timespec ts) {
	while(ts.tv_nsec >= NSEC_PER_SEC) {
		++(ts.tv_sec);
		ts.tv_nsec -= NSEC_PER_SEC;
	}
	while(ts.tv_nsec <= -NSEC_PER_SEC) {
		--(ts.tv_sec);
		ts.tv_nsec += NSEC_PER_SEC;
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

inline int is_ipv4_localhost(struct in6_addr* addr){
	const uint32_t dst_addr=((struct in_addr*)addr)->s_addr;
	return (dst_addr==htonl(INADDR_LOOPBACK))
					|| (dst_addr==htonl(INADDR_ANY));
}

inline int is_ipv6_localhost(struct in6_addr* addr){
	// is in6addr_loopback in host or network byte order ?
	return memcmp(&addr->s6_addr,&in6addr_loopback.s6_addr,16)==0;
}
