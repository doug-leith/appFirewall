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

 int position = strnlen(pathBuffer,256);
 while(position >= 0 && pathBuffer[position] != '/')
 {
		 position--;
 }

 strcpy(nameBuffer, pathBuffer + position + 1);

 //printf("path: %s\n\nname:%s\n\n", pathBuffer, nameBuffer);
 */
 
int find_proc(const char* target) {
	// search current processes for one matching target name
	int count = 0;
	char target_[MAXCOMLEN];
	// we only copy first 16 characters of name, since that's all that
	// get_pid_name gives us.
	strlcpy(target_,target,MAXCOMLEN);
	
	int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	pid_t pids[2 * bufsize / sizeof(pid_t)];
	bufsize =  proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
	size_t num_pids = (size_t)bufsize / sizeof(pid_t);

	if (bufsize == 0) {
		WARN("find_proc() problem getting list of PIDS: %s\n",strerror(errno));
		if (errno == EPERM) {
			// don't have permission to list PIDs
		}
		return -1;
	}
	
	// now walk through them
	int j;
	for (j=0; j< num_pids; j++) {
		int pid = pids[j];
		
		// get app name associated with process
		char name[MAXCOMLEN]; uint32_t status;
		if (get_pid_name(pid, name, &status)<0) {
			// problem getting name for PID, probably process has stopped
			// between call to proc_listpids() above and our call to get_pid_name()
			continue;
		}
		//printf("%s %d (%s)\n",name, pid,target_);
		if( (strcmp(name,target_)==0) && (status != SZOMB) ) {
			//printf("pgrep status %d (SSTOP %d)\n", status, SSTOP);
			count++;
		}
	}
	return count;
}
