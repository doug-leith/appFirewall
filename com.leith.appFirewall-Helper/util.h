//
//  util.h
//  com.leith.appFirewall-Helper
//

#ifndef util_h
#define util_h

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/un.h>
#include <sys/stat.h>

const static int verbose=1;          // debugging level
// apple logging to system.log
#include <os/log.h>
#define ERR_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define WARN_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define INFO_LOG(fmt, ...)  do{if (verbose) os_log(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)

#define ERR(fmt,args ...) do{char buf[32]; fprintf(stderr,"%s ERROR: ",now(buf)); fprintf(stdout, fmt,args);}while(0)
#define WARN(args ...) do{char buf[32];fprintf(stderr,"%s WARNING: ",now(buf)); fprintf(stdout, args);}while(0)
#define INFO(args ...) if (verbose) do{char buf[32]; fprintf(stdout, "%s: ",now(buf));fprintf(stdout, args);}while(0)
#define DEBUG2(args ...) if (verbose>1) fprintf(stdout, args)

#define LINEBUF_SIZE 4096 // max line size of dtrace line

char* now(char* buf);
int readn(int fd, void* buf, int n);
int read_line(int fd, char* inbuf, size_t *inbuf_used, char* line);
int bind_to_port(int port);

#endif /* util_h */
