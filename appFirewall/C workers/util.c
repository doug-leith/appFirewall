//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "util.h"

#define STR_SIZE 1024
static char error_msg[STR_SIZE];
static int force_helper_restart = 0;
static char data_path[STR_SIZE];
static char date[STR_SIZE], date_temp[STR_SIZE];

// stats
stats_t stats;

// logging level
int verbose = 1;

void set_logging_level(int_sw level) {
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
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_escapees_hits);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_t_escapees_misses);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_escapee_thread_count);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_dns_snaplen);
	init_cm_quantile(0.01, (double*)&quants, 3, &stats.cm_mdns_snaplen);
}

static pthread_mutex_t cm_mutex = MUTEX_INITIALIZER;
int cm_add_sample_lock(cm_quantile *cm, double sample) {
	// take lock
	TAKE_LOCK(&cm_mutex, "cm_add_sample_lock");
	int res = cm_add_sample(cm,sample);
	pthread_mutex_unlock(&cm_mutex);
	return res;
}

void print_stats() {
	TAKE_LOCK(&cm_mutex, "print_stats");
	INFO("pktap hits %d/misses %d, pidinfo hits %d/misses %d, pidinfo_cache hits %d/misses %d, waitinglist hits %d/misses %d, escapees fresh %d/stale %d/old %d hits %d/misses %d/gone away %d, escapee timeouts %d/%d, procname hits %d/guesses %d/notfound %d, fdtab same %d/changed %d/%d, DNS snaplen misses %d/count %d, mDNS snaplen misses %d/count %d, DNS snaplen shortfall %.2f/%.2f, mDNS snaplen shortfall %.2f/%.2f\ntiming 50th/90th percentiles: sniff %.2f/%.2f, not blocked %.2f/%.2f, blocked %.2f/%.2f, dns %.2f/%.2f, udp %.2f/%.2f, waitinglist hits %.2f/%.2f. waitinglist misses %.2f/%.2f, pidinfo cache hit %.2f/%.2f, pidinfo cache miss %.2f/%.2f\n",
	stats.pktap_hits,stats.pktap_misses, 
	stats.pidinfo_hits, stats.pidinfo_misses,
	stats.pidinfo_cachehits, stats.pidinfo_cachemisses,
	stats.waitinglist_hits,stats.waitinglist_misses,
	stats.num_escapees, stats.stale_escapees, stats.escapees_not_in_log,
	stats.escapees_hits,stats.escapees_misses, stats.escapees_goneaway,
	stats.escapee_timeouts,stats.num_escapees,
	stats.num_noguess, stats.num_guesses, stats.num_failed_guesses,
	stats.fdtab_same, stats.fdtab_changed, stats.fdtab_destchanged,
	stats.dns_snaplen_misses, stats.dns_count, stats.mdns_snaplen_misses, stats.mdns_count,
	cm_query(&stats.cm_dns_snaplen,0.5), cm_query(&stats.cm_dns_snaplen,0.9),
	cm_query(&stats.cm_mdns_snaplen,0.5), cm_query(&stats.cm_mdns_snaplen,0.9),
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
	pthread_mutex_unlock(&cm_mutex);
}

// swift interface
char* get_error_msg() {
	return error_msg;
}

int get_error_force() {
	return force_helper_restart;
}

void set_error_msg(char* msg, int force) {
	strlcpy(error_msg,msg,STR_SIZE);
	force_helper_restart = force;
}

char* get_path() {
	return data_path;
}

void set_path(const char* path) {
	strlcpy(data_path,path,STR_SIZE);
}

ssize_t readn(int fd, void* buf, ssize_t n) {
 // read n bytes from socket fd
	ssize_t res=0, posn=0;;
	while (posn<n) {
		//printf("posn=%d,n=%d\n",posn,n);
		res = recv(fd, buf+posn, (size_t)(n-res), 0);
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
  ssize_t read_posn=0;
  while (i < LINEBUF_SIZE) {
    if (read_posn == *inbuf_used) {
      // read from socket
      // TO DO: check that packet is from expected source IP/port (might be interleaved with a new request for example)
      ssize_t rv = read(fd, (void*)&inbuf[*inbuf_used], LINEBUF_SIZE - *inbuf_used);
      if (rv == 0) {
        WARN("read_line() connection closed.\n");
        return 0;
      }
      if (rv < 0) {
        if (errno == EAGAIN) {
           WARN("read_line() connection timeout\n");
        } else {
           ERR("read_line() connection error: %s\n",strerror(errno));
        }
        return -1;
      }
      *inbuf_used += (size_t)rv;
    }
    line[i++] = inbuf[read_posn++]; // advance read position within buffer
    if (line[i-1]=='\n') break; // have hit a newline, stop
  }
  if (i==LINEBUF_SIZE) {
    ERR("read_line() line larger than %d.\n",LINEBUF_SIZE);
    return -1;
  }
  line[i]='\0'; // terminate line as string, makes for easier printing when debugging
  // shift buffer contents so next line starts at posn 0
  memmove(inbuf,inbuf+(size_t)read_posn,*inbuf_used-(size_t)read_posn);
  *inbuf_used -= (size_t)read_posn;

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

  // Trim leading space, we cap trimming at 1024 to be safe
  int count=0;
  size_t max = strnlen(str,STR_SIZE);
  while(isspace((unsigned char)*str) && (count<max)) {str++; count++;}

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strnlen(str,STR_SIZE) - 1;
  count=0;
  while( (end > str) && isspace((unsigned char)*end) && (count<max)) {end--; count++;}

  // Write new null terminator character
  end[1] = '\0';

  return str;
}


void redirect_stdout(const char* appLog) {
	// set up logging
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,appLog,STR_SIZE);
	int logfd = open(path,O_RDWR|O_CREAT|O_APPEND,0644);
	if (logfd == -1) {
		ERR("Failed to open logfile %s, logging disabled: %s\n",path,strerror(errno));
	}
	//if (!isatty(fileno(stdout))) {
		if (dup2(logfd,STDOUT_FILENO)<0) WARN("Problem redirecting stdout to %s: %s",appLog, strerror(errno)); // redirect stdout to log file
		if (dup2(logfd,STDERR_FILENO)<0) WARN("Problem redirecting stderr to %s: %s",appLog, strerror(errno));  // ditto stderr
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

inline int is_ipv4_localhost(struct in6_addr* addr){
	const uint32_t dst_addr=((struct in_addr*)addr)->s_addr;
	return (dst_addr==htonl(INADDR_LOOPBACK))
					|| (dst_addr==htonl(INADDR_ANY));
}

inline int is_ipv6_localhost(struct in6_addr* addr){
	// is in6addr_loopback in host or network byte order ?
	return memcmp(&addr->s6_addr,&in6addr_loopback.s6_addr,16)==0;
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

char* get_date() {
	time_t t; time(&t);
	strftime(date,STR_SIZE,"%d %b %H:%M:%S %Y",localtime(&t));
	return date;
}

char* get_file_modify_time(const char *path) {
    struct stat attr;
    if (lstat(path, &attr)<0) {
    	WARN("Problem calling lstat to get modify time of %s: %s\n",path,strerror(errno));
    	return NULL;
		}
    strftime(date_temp,STR_SIZE,"%d %b %H:%M:%S %Y",localtime(&attr.st_mtime));
    return date_temp;
}

int find_if(struct ifaddrs *ifap, int af, struct in6_addr *addr2) {
	struct ifaddrs *dev;
	for(dev=ifap; dev; dev=dev->ifa_next) {
		DEBUG2("interface %s ...",dev->ifa_name);
		struct sockaddr *addr = dev->ifa_addr;
		if (af != addr->sa_family) continue;
		if (af == AF_INET) {
			if (((struct sockaddr_in*)addr)->sin_addr.s_addr != ((struct in_addr*)addr2)->s_addr)
				continue;
		} else {
			if (memcmp(&((struct sockaddr_in6*)addr)->sin6_addr.s6_addr, &addr2->s6_addr, 16)!=0) continue;
		}
		// have found interface with matching address
		u_int flags = dev-> ifa_flags;
		if (flags & IFF_UP)
			return ((flags & IFF_POINTOPOINT) != 0);
		else
			return -1;  // interface is down
	}
	return -2; // interface not found, its a remote address.
}

int is_ppp(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr) {
	struct ifaddrs *ifap;
	if (getifaddrs(&ifap)<0) {
		ERR("Couldn't get list of interfaces from getifaddrs(): %s", strerror(errno));
		return 0;
	}
	int res1,res2;
	res1 = find_if(ifap, af, src_addr);
	if (res1>=0) { // found matching interface, return PPP status
		freeifaddrs(ifap);
		return res1;
	}
	res2 = find_if(ifap, af, dst_addr);
	freeifaddrs(ifap);
	if (res2>=0) { // found matching interface, return PPP status
		return res2;
	}
	return -1; // interface is down or has gone away
}

static int unit_testing = 0;
void set_unit_testing() {
	unit_testing = 1;
}

int get_unit_testing() {
	return unit_testing;
}

