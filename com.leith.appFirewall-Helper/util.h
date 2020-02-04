//
//  util.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
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
#include <ctype.h>

const static int verbose=1;          // debugging level
// apple logging to system.log
#include <os/log.h>
#define ERR_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define WARN_LOG(fmt, ...) do{os_log_error(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)
#define INFO_LOG(fmt, ...)  do{if (verbose) os_log(OS_LOG_DEFAULT,fmt, ##__VA_ARGS__);}while(0)

#define ERR(fmt,args ...) do{char buf[32]; fprintf(stderr,"%s ERROR: ",now(buf)); fprintf(stdout, fmt,args);}while(0)
#define WARN(args ...) do{char buf[32];fprintf(stderr,"%s WARNING: ",now(buf)); fprintf(stdout, args);}while(0)
#define INFO(args ...) if (verbose) do{char buf[32]; fprintf(stdout, "%s: ",now(buf));fprintf(stdout, args);}while(0)
#define INFO2(args ...) if (verbose>1) do{fprintf(stdout, args);}while(0)
#define DEBUG2(args ...) if (verbose>2) fprintf(stdout, args)

#define LINEBUF_SIZE 4096 // max line size of readn line
#define RECV_TIMEOUT 10 // 10s for socket read timeout
#define SND_TIMEOUT 10 // 10s for socket send timeout
#define STR_SIZE 1024

char* now(char* buf);
ssize_t readn(int fd, void* buf, ssize_t n);
int read_line(int fd, char* inbuf, size_t *inbuf_used, char* line);
int bind_to_port(int port, int q);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);
void set_recv_timeout(int sockfd, int timeout);
void set_snd_timeout(int sockfd, int timeout);
struct timespec timespec_add(struct timespec ts1, struct timespec ts2);
char *trimwhitespace(char *str);
FILE* run_cmd_pipe(char* cmd, char* arg, int *pid);
int run_cmd(char* cmd, int t);
int readline_timed(char* buf, int len, FILE* fp, int t);

// defs for functions in codesign.m
int check_signature(int pid, int port);
int get_sock_pid(int sock, int port);
int check_file_signature(char* path, int force);
#endif /* util_h */
