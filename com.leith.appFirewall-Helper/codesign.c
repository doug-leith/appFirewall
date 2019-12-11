//
//  codesign.c
//  appFirewall
//
//  Created by Doug Leith on 26/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include <stdio.h>
#include <Security/Security.h>
#include "util.h"

#define identifier "com.leith.appFirewall"
#define cert_cn "Apple Development: doug.leith@tcd.ie (8JB83FAF5R)"
#define ASCII 1536 //CFString ascii encoding

int get_sock_pid(int sock, int port) {
	pid_t pid; socklen_t pid_size = sizeof(pid);
	if (getsockopt(sock, SOL_LOCAL,  LOCAL_PEERPID, &pid, &pid_size)<0) {
		WARN("getsockopt() LOCAL_PEERPID for port %d: %s\n", port,strerror(errno));
		return -1;
	}
	return pid;
}

int check_signature(int sock, int port){
	// check signature of client connected to socket is valid (signed ok and by right person).
	// quite slow, takes about 100ms
	
	pid_t pid = get_sock_pid(sock, port); if (pid<0) return -1;
	INFO("client pid=%d for port %d\n", pid, port);
		
	// get reference to code using PID
	SecCodeRef codeRef;
	CFNumberRef pid_ = CFNumberCreate(NULL,kCFNumberIntType,&pid);
	CFMutableDictionaryRef attr = CFDictionaryCreateMutable(NULL,10,NULL,NULL);
	CFDictionaryAddValue(attr,kSecGuestAttributePid,pid_);
	OSStatus status =SecCodeCopyGuestWithAttributes(NULL, attr, kSecCSDefaultFlags, &codeRef);
	CFRelease(attr); CFRelease(pid_);
	if (status != errSecSuccess) {
		CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
		WARN("problem getting code ref for PID %d on port %d: %s\n",pid,port, CFStringGetCStringPtr(err_str,1536));
		CFRelease(err_str);
		return -1;
	}
	
	// check code signature is valid and meets our requirements
	char str[1024];
	//sprintf(str,"identifier %s and anchor apple generic and certificate leaf[subject.CN] = \"%s\"", identifier, cert_cn);
	sprintf(str,"identifier %s and anchor apple generic", identifier);
	CFStringRef req_str = CFStringCreateWithCString(NULL,str,ASCII);
	SecRequirementRef req;
	SecRequirementCreateWithString(req_str, kSecCSDefaultFlags, &req);
	// check signature against embedded requirements
	status = SecStaticCodeCheckValidity(codeRef, kSecCSCheckAllArchitectures, req);
	CFRelease(req); CFRelease(req_str);
	
	CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
	INFO("signing status on port %d: %s\n",port,CFStringGetCStringPtr(err_str,ASCII));
	CFRelease(err_str);
	if (1) {//}(status != errSecSuccess) {
		// get some extra debug info
		SecCSFlags flags = kSecCSInternalInformation
		| kSecCSSigningInformation
		| kSecCSRequirementInformation
		| kSecCSInternalInformation;
		CFDictionaryRef api;
		SecCodeCopySigningInformation(codeRef, flags, &api);
		CFStringRef id = CFDictionaryGetValue(api, kSecCodeInfoIdentifier);
		INFO("signature identifier on port %d: %s\n",port,CFStringGetCStringPtr(id,ASCII));
		//CFRelease(id); // releasing api releases id string
		CFRelease(api);
		
		SecRequirementRef req;
		SecCodeCopyDesignatedRequirement(codeRef, kSecCSDefaultFlags, &req);
		CFStringRef req_str;
		SecRequirementCopyString(req, kSecCSDefaultFlags, &req_str);
		INFO("requirements on port %d: %s\n",port,CFStringGetCStringPtr(req_str,ASCII));
		CFRelease(req_str); CFRelease(req);
		CFRelease(codeRef);
		#ifdef DEBUG
		// appFirewall will fail sign check when compiled for testing/debugging, but its ok
		INFO("DEBUG enabled, passed anyway\n");
		//return pid;
		return -1;
		#else
		return -1;
		#endif
	}
	INFO("passed signature check on port %d\n",port);
	CFRelease(codeRef);
	return pid;
}
