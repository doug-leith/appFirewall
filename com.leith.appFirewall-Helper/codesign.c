//
//  codesign.c
//  appFirewall
//
//  Created by Doug Leith on 26/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include <stdio.h>
#include <Security/Security.h>

int check_signature(int pid){
	//int pid = 43483;
	// get reference to code using PID
	SecCodeRef codeRef;
	CFNumberRef pid_ = CFNumberCreate(NULL,kCFNumberIntType,&pid);
	CFMutableDictionaryRef attr = CFDictionaryCreateMutable(NULL,10,NULL,NULL);
	CFDictionaryAddValue(attr,kSecGuestAttributePid,pid_);
	OSStatus status =SecCodeCopyGuestWithAttributes(NULL, attr, kSecCSDefaultFlags, &codeRef);
	CFRelease(attr); CFRelease(pid_);
	if (status != errSecSuccess) {
		CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
		printf("problem getting code ref for PID %d: %s\n",pid, CFStringGetCStringPtr(err_str,1536));
		CFRelease(err_str);
		return -1;
	}

	// check signature against embedded requirements
	status = SecStaticCodeCheckValidity(codeRef, kSecCSCheckAllArchitectures, NULL);
	if (status != errSecSuccess) {
		CFStringRef err_str = SecCopyErrorMessageString(status,NULL);
		printf("signing error: %s\n",CFStringGetCStringPtr(err_str,1536));
		CFRelease(err_str);
		
		// get some extra debug info
		SecCSFlags flags = kSecCSInternalInformation
		| kSecCSSigningInformation
		| kSecCSRequirementInformation
		| kSecCSInternalInformation;
		CFDictionaryRef api; // not mutable, no need to release
		SecCodeCopySigningInformation(codeRef, flags, &api);
		CFStringRef id = CFDictionaryGetValue(api, kSecCodeInfoIdentifier);
		printf("signature identifier: %s\n",CFStringGetCStringPtr(id,1536));
		CFRelease(id);
		
		SecRequirementRef req;
		SecCodeCopyDesignatedRequirement(codeRef, kSecCSDefaultFlags, &req);
		CFStringRef req_str;
		SecRequirementCopyString(req, kSecCSDefaultFlags, &req_str);
		printf("requirements: %s\n",CFStringGetCStringPtr(req_str,1536));
		CFRelease(req_str); CFRelease(req);
		CFRelease(codeRef);
		return -1;
	}
	printf("passed signature check\n");
	CFRelease(codeRef);
	return 0;
}
