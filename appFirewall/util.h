#ifndef util_h
#define util_h

#include <netinet/in.h>
#include <sys/errno.h>

const static int verbose=1;          // debugging level

#include <os/log.h> // apple logging
#define ERR(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define WARN(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define INFO(fmt, ...)  do{if (verbose) os_log(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)

//#define ERR(args ...) do{fprintf(stderr,"ERROR: "); fprintf(stderr, args);}while(0)
//#define WARN(args ...) do{fprintf(stderr,"WARNING: "); fprintf(stderr, args);}while(0)
//#define INFO(args ...) if (verbose) fprintf(stdout, args)
#define DEBUG2(args ...) if (verbose>1) fprintf(stdout, args)

// raise SIGCHLD event in C to display popup to user before exiting on error.
#define EXITFAIL(args ...) do{char str[1024]; sprintf(str,args); set_error_msg(str);raise(SIGCHLD);}while(0)

#define BUFSIZE 256
#define LINEBUF_SIZE 4096 // max line size of dtrace line

char* get_error_msg(void);
void set_error_msg(char* msg);
char* get_path(void);
void set_path(const char* path);
int readn(int fd, void* buf, int n);
int read_line(int fd, char* inbuf, size_t *inbuf_used, char* line);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);

#endif
