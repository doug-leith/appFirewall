//
//  install_helper.swift
//  appFirewall
//
//  Created by Doug Leith on 26/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

// handlers for management of appFirewall-Helper process

import Foundation
import ServiceManagement
import os

func pgrep(Name: String)->Int {
	// get number of running processing matching Name
	let task = Process();
	task.launchPath = "/usr/bin/pgrep"
	task.arguments = ["-x",Name]
	let pipe = Pipe()
	task.standardOutput = pipe
	task.launch()
	let resp = pipe.fileHandleForReading.readDataToEndOfFile()
	task.waitUntilExit()
	// resp is a Data object i.e. a bytebuffer
	// so convert to string
	let resp_str = (String(data: resp, encoding: .utf8) ?? "-1").trimmingCharacters(in: .whitespacesAndNewlines)
	print("pgrep "+Name+" response: "+resp_str)
	if (resp.count == 0) {
		print(Name+" binary not running, null pgrep output")
		return 0
	}
	let resp_lines = resp_str.split { $0.isNewline }
	var pids : Array<Int>=[]
	for line in resp_lines {
		let pid = Int(line) ?? -1
		if (pid  < 0) {
			print("Problem parsing pgrep output for "+Name+", not an int: ",resp_lines)
			return -1
		}
		pids.append(pid)
	}
	//print(pids)
	return pids.count
}

func is_app_already_running()->Bool {
	let pid_count = pgrep(Name : "appFirewall")
	if (pid_count < 0) {
		print("pgrep error, halt.")
		return true // or could continue ?
	} else if (pid_count == 0) {
		print("appFirewall is not already running, continue.")
		return false
	} else {
		print("appFirewall already running, halt.")
		return true
	}
}

func is_helper_running(Name: String)->Bool {
	// is helper binary there ?
	//print("is_helper_running()")
	let path = "/Library/PrivilegedHelperTools/"+Name
	if !FileManager.default.fileExists(atPath: path) {
		print("helper binary not found at "+path)
		return false
	}
	let pid_count = pgrep(Name : Name)
	if (pid_count < 0) {
		print("pgrep problem")
		return false // is this the right thing to do ?
	} else if (pid_count == 0) {
		print("helper binary not running")
		return false
	} else {
		print("helper binary installed and running")
		return true
	}
}

func get_helper_version(Name: String)->Int {
	// we extract this from the helper Info.plist
	let path = "/Library/LaunchDaemons/"+Name+".plist"
	if let dict = NSDictionary(contentsOfFile: path) as? Dictionary<String, AnyObject> {
			//print(dict)
			guard let version:Int = dict["Version"] as? Int else {return -1}
			print(String(format:"helper version is %d",version))
			return version
	} else {
		print("problem reading helper version from "+path)
		return -1
	}
}

func start_helper() {
	// install appFirewall-Helper if not already installed
	
	/*
	// clear defaults
	if let bundleID = Bundle.main.bundleIdentifier {
			UserDefaults.standard.removePersistentDomain(forName: bundleID)
	}*/
	
	/*let app_version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as! String
		let helper_version = UserDefaults.standard.string(forKey: "helper_version")
	*/
	let kHelperToolName:String = "com.leith.appFirewall-Helper"

	let REQUIRED_VERSION = 1
	if (is_helper_running(Name: kHelperToolName)) {
		let version = get_helper_version(Name: kHelperToolName)
		if (version == REQUIRED_VERSION) {
			print(String(format:"helper "+kHelperToolName+", version %d already installed.", version))
			return // right version of helper already installed
		}
	}
	
	// ask user for authorisation to install helper
	var authRef:AuthorizationRef?
	let authItem = AuthorizationItem(name: kSMRightBlessPrivilegedHelper,valueLength: 0, value:UnsafeMutableRawPointer(bitPattern: 0), flags: 0)
	var authItems = [authItem]
	var authRights:AuthorizationRights = AuthorizationRights(count: UInt32(authItems.count), items:&authItems)
	let authFlags: AuthorizationFlags = [
		[],
		.extendRights,
		.interactionAllowed,
		.preAuthorize
	]
	let status = AuthorizationCreate(&authRights, nil, authFlags, &authRef)
	if (status != errAuthorizationSuccess){
		let error = NSError(domain:NSOSStatusErrorDomain, code:Int(status), userInfo:nil)
		exit_popup(msg:"Authorization error: \(error)")
	}else{
		// We have authorisation from user, go ahead and install helper
		// Call SMJobBless to verify appFirewall-Helper and,
		// once verification has passed, to install the
		// helper.  The embedded launchd.plist
		// is extracted and placed in /Library/LaunchDaemons and then loaded.
		// The helper executable is placed in /Library/PrivilegedHelperTools.
		// See https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless
		var cfError: Unmanaged<CFError>? = nil
		if !SMJobBless(kSMDomainSystemLaunchd, kHelperToolName as CFString, authRef, &cfError) {
			let blessError = cfError!.takeRetainedValue()
			exit_popup(msg:"Problem installing helper: \(blessError), exiting.")
		}else{
			print(kHelperToolName+" installed successfully")
		}
	}
}
