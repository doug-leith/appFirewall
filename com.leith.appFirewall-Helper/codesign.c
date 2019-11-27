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

int check_signature(int sock, int port){

	pid_t pid; socklen_t pid_size = sizeof(pid);
	if (getsockopt(sock, SOL_LOCAL,  LOCAL_PEERPID, &pid, &pid_size)<0) {
		ERR("getsockopt() LOCAL_PEERPID for port %d: %s", port,strerror(errno));
		return -1;
	}
	printf("client pid=%d for port %d\n", pid, port);
	
	// get reference to code using PID
	SecCodeRef codeRef;
	CFNumberRef pid_ = CFNumberCreate(NULL,kCFNumberIntType,&pid);
	CFMutableDictionaryRef attr = CFDictionaryCreateMutable(NULL,10,NULL,NULL);
	CFDictionaryAddValue(attr,kSecGuestAttributePid,pid_);
	OSStatus status =SecCodeCopyGuestWithAttributes(NULL, attr, kSecCSDefaultFlags, &codeRef);
	CFRelease(attr); CFRelease(pid_);
	if (status != errSecSuccess) {
		CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
		printf("problem getting code ref for PID %d on port %d: %s\n",pid,port, CFStringGetCStringPtr(err_str,1536));
		CFRelease(err_str);
		return -1;
	}

	// check signature against embedded requirements
	status = SecStaticCodeCheckValidity(codeRef, kSecCSCheckAllArchitectures, NULL);
	if (status != errSecSuccess) {
		CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
		printf("signing error on port %d: %s\n",port,CFStringGetCStringPtr(err_str,1536));
		CFRelease(err_str);
		
		// get some extra debug info
		SecCSFlags flags = kSecCSInternalInformation
		| kSecCSSigningInformation
		| kSecCSRequirementInformation
		| kSecCSInternalInformation;
		CFDictionaryRef api; // not mutable, no need to release
		SecCodeCopySigningInformation(codeRef, flags, &api);
		CFStringRef id = CFDictionaryGetValue(api, kSecCodeInfoIdentifier);
		printf("signature identifier on port %d: %s\n",port,CFStringGetCStringPtr(id,1536));
		
		SecRequirementRef req;
		SecCodeCopyDesignatedRequirement(codeRef, kSecCSDefaultFlags, &req);
		CFStringRef req_str;
		SecRequirementCopyString(req, kSecCSDefaultFlags, &req_str);
		printf("requirements on port %d: %s\n",port,CFStringGetCStringPtr(req_str,1536));
		CFRelease(req_str); CFRelease(req);
		CFRelease(codeRef);
		#ifdef DEBUG
		// appFirewall will fail sign check when compiled for testing/debugging, but its ok
		return 0;
		#else
		return -1;
		#endif
	}
	printf("passed signature check on port %d\n",port);
	CFRelease(codeRef);
	return 0;
}
