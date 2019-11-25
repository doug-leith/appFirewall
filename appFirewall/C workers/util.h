#ifndef util_h
#define util_h

#include <stdio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <string.h>
#include <ctype.h>
#include "percentile.h"

extern int verbose;          // debugging level

/*#include <os/log.h> // apple logging
#define ERR(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define WARN(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define INFO(fmt, ...)  do{if (verbose) os_log(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
*/

#define APPLOGFILE "app_log.txt"

#define ERR(args ...) do{fprintf(stdout,"ERROR: "); fprintf(stderr, args);}while(0)
#define WARN(args ...) do{fprintf(stdout,"WARNING: "); fprintf(stderr, args);}while(0)
#define INFO(args ...) if (verbose) fprintf(stdout, args)
#define INFO2(args ...) if (verbose>1) fprintf(stdout, args)
#define DEBUG2(args ...) if (verbose>2) fprintf(stdout, args)

// raise SIGCHLD event in C to display popup to user before exiting on error.
#define EXITFAIL(args ...) do{char str[1024]; sprintf(str,args); set_error_msg(str);raise(SIGCHLD);}while(0)

#define LINEBUF_SIZE 4096 // max line size of readn line
#define STR_SIZE 1024
#define RECV_TIMEOUT 10 // 10s for socket read timeout
#define SND_TIMEOUT 20 // 20s for socket send timeout, nice and long

typedef struct {
	int pidinfo_hits, pidinfo_misses;
	int pidinfo_cachehits, pidinfo_cachemisses;
	int dtrace_hits, dtrace_misses;
	int waitinglist_hits, waitinglist_misses;
	cm_quantile cm_t_notblocked, cm_t_blocked, cm_t_waitinglist_hit, cm_t_waitinglist_miss, cm_t_dns,cm_t_pidinfo_cache_hit, cm_t_pidinfo_cache_miss, cm_t_sniff, cm_t_udp, cm_t_escapees_hits, cm_t_escapees_misses, cm_escapee_thread_count;
	int num_escapees,escapees_not_in_log,stale_escapees,escapees_hits,escapees_misses;
} stats_t;

extern stats_t stats;

char* get_error_msg(void);
void set_error_msg(char* msg);

char* get_path(void);
void set_path(const char* path);

int readn(int fd, void* buf, int n);
int read_line(int fd, char* inbuf, size_t *inbuf_used, char* line);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);
int is_ipv4_localhost(struct in6_addr* addr);
int is_ipv6_localhost(struct in6_addr* addr);
int robust_inet_pton(int *af, const char * restrict src, void * restrict dst);
const char* robust_inet_ntop(int *af, const void * restrict src, char * restrict dst, socklen_t size);
void set_recv_timeout(int sockfd, int timeout);
void set_snd_timeout(int sockfd, int timeout);

char *trimwhitespace(char *str);
void redirect_stdout(void);

void print_stats(void);
void set_logging_level(int level);
void init_stats(void);

struct timespec timespec_add(struct timespec ts1, struct timespec ts2);

#endif
