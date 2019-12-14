//
//  pgrep.c
//  appFirewall
//
//  Created by Doug Leith on 14/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "pgrep.h"

/*// if  we need to get the long name for process can use this:
 // (taken from https://stackoverflow.com/questions/12273546/get-name-from-pid)

 char pathBuffer [PROC_PIDPATHINFO_MAXSIZE];
 proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));

 char nameBuffer[256];

 int position = strlen(pathBuffer);
 while(position >= 0 && pathBuffer[position] != '/')
 {
		 position--;
 }

 strcpy(nameBuffer, pathBuffer + position + 1);

 printf("path: %s\n\nname:%s\n\n", pathBuffer, nameBuffer);
 */
 
int find_proc(const char* target) {
	// search current processes for one matching target name
	int count = 0;
	char target_[MAXCOMLEN];
	// we only copy dfirst 16 characters of name, since that's all that
	// get_pid_name gives us.
	strlcpy(target_,target,MAXCOMLEN);
	
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = (size_t)bufsize / sizeof(pid_t);

	// now walk through them
	int j;
	for (j=0; j< num_pids; j++) {
		int pid = pids[j];
		
		// get app name associated with process
		// this call consumes around 10% of executiin time of refresh_active_conns()
		char name[MAXCOMLEN];
		if (get_pid_name(pid, name)<0) {
			// problem getting name for PID, probably process has stopped
			// between call to proc_listpids() above and our call to get_pid_name()
			continue;
		}
		//printf("%s %d (%s)\n",name, pid,target_);
		if( strcmp(name,target_)==0) count++;
	}
	return count;
}
