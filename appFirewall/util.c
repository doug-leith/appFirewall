
#include "util.h"
#include <string.h>

static char error_msg[1024];
static char data_path[1024];

// swift interface
char* get_error_msg() {
	return error_msg;
}

void set_error_msg(char* msg) {
	strcpy(error_msg,msg);
}

char* get_path() {
	return data_path;
}

void set_path(const char* path) {
	strcpy(data_path,path);
}
