//
//  cHelpers.swift
//  appFirewall
//
//  Created by Doug Leith on 26/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Foundation
import AppKit

// -------------------------------------
// C helpers

func setup_sig_handlers() {
	// if a C routine fatally fails it raises a SIGHUP signal
	// and we catch it here to raise an popup to inform user
	// and exit gracefully
	/*let handler: @convention(c) (Int32) -> () = { sig in
		print("signal ",String(sig)," caught")
		exit_popup(msg:String(cString: get_error_msg()), force:Int(get_error_force()))
	}*/
	let backtrace_handler: @convention(c) (Int32) -> () = { sig in
		// handle the signal

		// save backtrace, we'll catch this when restart (of course that's hoping we are not in such a bad state
		// that this fails e.g. we still need to have malloc functioning for Thread.callStackSymbols to work)
		// NB: to map from backtrace output so line number in source use atos. e.g. for the line "0 appFirewall 0x00000001000535ef " in backtrace "atos -o appFirewall.app/Contents/MacOS/appFirewall 0x00000001000535ef" returns "AppDelegate.applicationWillFinishLaunching(_:) (in appFirewall) (AppDelegate.swift:182)"
		UserDefaults.standard.set(Thread.callStackSymbols, forKey: "backtrace")
		UserDefaults.standard.set(sig, forKey: "signal")
		// print to log
		print("signal ", sig)
		Thread.callStackSymbols.forEach{print($0)}
		exit(1)
	}

	/*var action = sigaction(__sigaction_u:
												unsafeBitCast(handler, to: __sigaction_u.self),
												sa_mask: 0,
												sa_flags: 0)
	sigaction(SIGUSR1, &action, nil)*/
	
	// and dump backtrace on other fatal errors
	var action = sigaction(__sigaction_u: unsafeBitCast(backtrace_handler,
											to: __sigaction_u.self),
												sa_mask: 0,
												sa_flags: 0)
	sigaction(SIGSEGV, &action, nil)
	sigaction(SIGABRT, &action, nil)
	sigaction(SIGIOT, &action, nil)
	sigaction(SIGBUS, &action, nil)
	sigaction(SIGFPE, &action, nil)
	sigaction(SIGILL, &action, nil)}

// -------------------------------------
// C helpers
func make_data_dir() {
	// create Library/Application Support/appFirewall directory if
	// it doesn't already exist, and pass path on to C routines
	let paths = NSSearchPathForDirectoriesInDomains(.applicationSupportDirectory, .userDomainMask, true);
	let appname = Bundle.main.infoDictionary!["CFBundleName"] as! String
	let path = paths[0]+"/"+appname
	if !FileManager.default.fileExists(atPath: path) {
			do {
					try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
					print("created "+path)
			} catch {
					print("problem making data_dir: "+error.localizedDescription);
			}
	}
	// and tell C helpers what the path we're using is
	set_path(path + "/")
	print("storage path "+path)
}

func need_log_rotate(logName: String)->Bool {
	let path = String(cString: get_path())
	let logfile = path + logName
	var fileSize : UInt64 = 0
	do {
		let attr = try FileManager.default.attributesOfItem(atPath: logfile)
		fileSize = attr[FileAttributeKey.size] as! UInt64
	} catch {
			print("Problem rotating log getting size of "+logfile+": "+error.localizedDescription)
	}
	print("logrotate ",logfile," size ",String(fileSize))
	if (fileSize < 5000000) { // 5M
		return false
	} else {
		return true
	}
}

func log_rotate(logName: String) {
	// rotate human readable log file if getting too large
	let path = String(cString: get_path())
	let logfile = path + logName
	// rotate
	print("Rotating log, trying to remove "+logfile+String(5))
	if FileManager.default.fileExists(atPath: logfile+String(5)) {
		do {
			try FileManager.default.removeItem(atPath:logfile+String(5))
		} catch {
			print("Rotating log, removing "+logfile+String(5)+": "+error.localizedDescription)
		}
	}
	for i in (0...4).reversed() {
		if FileManager.default.fileExists(atPath: logfile+String(i)) {
			print("Rotating ",logfile+String(i)," to ",logfile+String(i+1))
			do {
				try FileManager.default.moveItem(atPath:logfile+String(i), toPath: logfile+String(i+1))
			} catch {
				print("Rotating log "+logfile+String(i)+": "+error.localizedDescription)
			}
		} else {
			print("Rotating: ",logfile+String(i)," doesn't exist, continuing")
		}
	}
	do {
		try FileManager.default.moveItem(atPath:logfile, toPath: logfile+"0")
		} catch {
				print("Rotating log, moving "+logfile+" to ", logfile+"0: "+error.localizedDescription)
		}
}

func save_state() {
	DispatchQueue.global(qos: .background).async {
		save_log(Config.logName)
		save_connlist(get_blocklist(),Config.blockListName); save_connlist(get_whitelist(),Config.whiteListName)
		save_dns_cache(Config.dnsName); save_dns_conn_list(Config.dnsConnListName)
	}
}

func load_state() {
	load_log(Config.logName, Config.logTxtName);
	load_connlist(get_blocklist(),Config.blockListName); load_connlist(get_whitelist(),Config.whiteListName)
	load_dns_cache(Config.dnsName);
	// we distribute app with preconfigured dns_conn cache so that
	// can guess process names of common apps more quickly
	let filePath = String(cString:get_path())
	let backupPath = Bundle.main.resourcePath ?? "./"
	if (load_dns_conn_list(filePath, Config.dnsConnListName)<0) {
		print("Falling back to loading dns_conn_list from ",backupPath)
		load_dns_conn_list(backupPath, Config.dnsConnListName)
	}
}

// -------------------------------------
// UI Helpers

func exit_popup(msg: String, force:Int) { // doesn't return
	print(msg)
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "Restart App")
	alert.addButton(withTitle: "Exit App")
	let response = alert.runModal()
	if (force > 0) {
		// force reinstall of helper on restart of app
		UserDefaults.standard.set(true, forKey: "force_helper_restart")
	}
	if (response == .alertFirstButtonReturn) {
		//restart
		print("Restarting app ...")
		restart_app()
	} else {
		print("Exiting app.")
		exit(1) // hard shutdown
	}
}

func restart_app() {
	// flag to app that its been restarted
	UserDefaults.standard.set(true, forKey: "restart")
	// relaunch app
	NSWorkspace.shared.launchApplication("appFirewall")
	/*let url = URL(fileURLWithPath: Bundle.main.resourcePath!)
	let path = url.deletingLastPathComponent().deletingLastPathComponent().absoluteString
	let task = Process()
	task.launchPath = "/usr/bin/open"
	task.arguments = [path]
	task.launch()*/
	
	// and stop our copy of app
  DispatchQueue.main.async{
  	NSApp.terminate(nil) // tidy shutdown, calls applicationWillTerminate()
	}
}

func error_popup(msg: String) {
	print(msg) // print error to log
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "OK")
	alert.runModal()
}

func quiet_error_popup(msg: String, quiet: Bool) {
	if !quiet {
		DispatchQueue.main.async {
			error_popup(msg: msg)
		}
	} else { // if quiet, just print error to log
		print(msg)
	}
}

func setColor(cell: NSTableCellView, udp: Bool, white: Int, blocked: Int) {
	if (white==1) {
		cell.textField?.textColor = NSColor.systemGreen
		return
	}
	if ( !udp && (blocked==1) ) {// blocked from blocklist
		cell.textField?.textColor = NSColor.red
	} else if ( !udp && (blocked==2) ) { // blocked from hosts file list
		cell.textField?.textColor = NSColor.orange
	} else if ( !udp && (blocked==3) ) { // blocked from blocklists file list
		cell.textField?.textColor = NSColor.brown
	} else { // not blocked
		cell.textField?.textColor = NSColor.systemGreen
	}
}

import Compression

func getSampleDir()->String? {
	let sampleDir = String(cString:get_path())+"samples/"
	if !FileManager.default.fileExists(atPath: sampleDir) {
			do {
					try FileManager.default.createDirectory(atPath: sampleDir, withIntermediateDirectories: true, attributes: nil)
					print("created "+sampleDir)
			} catch {
					print("WARNING: problem making sample dir: "+error.localizedDescription);
					return nil
			}
	}
	return sampleDir
}

func uploadSample(str: String, type: String) {
  // disable uploads
  /*
	var request = URLRequest(url: Config.sampleURL); request.httpMethod = "POST"
	let uploadData=(type+"="+String(str)+"&compression=none").data(using: .ascii)
	let session = URLSession(configuration: .default)
	let task = session.uploadTask(with: request, from: uploadData)
			{ data, response, error in
			if let error = error {
					print ("WARNING: error when sending app sample: \(error)")
					return
			}
			if let resp = response as? HTTPURLResponse {
				if !(200...299).contains(resp.statusCode) {
					print ("WARNING: server error when sending app sample: ",resp.statusCode)
				}
			}
	}
	task.resume()
	session.finishTasksAndInvalidate()
 */
}

func sampleApp(fname: String, lines: [String], app:String)->String {
	// upload a sample from the connection log for a specified app
	var log_lines: [String] = lines
	if (log_lines.count == 0) {
		// load lines from log file
		let path = String(cString:get_path())+fname
		do {
			// read log.  it won't be larger than 5MB since we rotate it otherwise
			// so its ok to read into memory
			flush_logtxt()
			let log_str : String = try String(contentsOfFile: path, encoding: String.Encoding.utf8)
			log_lines = log_str.components(separatedBy: "\n")
			if (log_lines.count == 0) {
				let msg = "Connection log is empty!"
				print(msg)
				return msg
			}
		} catch {
			let msg = "WARNING: Problem reading connection log " + path + ":" + error.localizedDescription
			print(msg)
			return msg
		}
	}
	// now extract all the log lines for the chosen app
	log_lines.removeAll{!$0.contains(app)}
	let lines_selected = log_lines
	
	if (lines_selected.count == 0) {
		let msg = "No connections logged for " + app;
		print(msg)
		return msg
	}
	
	// concatenate the lines back together
	// locale/time zone gives a v rough idea of location, so we can tell if app
	// behaviour depends on whether in Europe, US, China etc
	var str: String = "#OS version:\n"+ProcessInfo.processInfo.operatingSystemVersionString+"\n"
	str = str + "#Locale:\n"+Locale.current.identifier+"\n"
	str = str + NSTimeZone.local.identifier+"\n"
	str = str + NSTimeZone.system.identifier+"\n"
	str = str + "#App connections\n"
	str = str + lines_selected.joined(separator:"\n")
	//print("Sample from app connection log:")
	//print(str)
	
	// TO DO: gzip the upload to save bandwidth.  Files are usually quite
	// small though (10-100K) so sending uncompressed doesn't seem like a big
	// deal plus using gzip from Swift seems a bit nasty.
	// zip data to save upload bandwidth
	/*let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: str.count)
	var sourceBuffer = Array(str.utf8)
	let algorithm = COMPRESSION_ZLIB
	let compressedSize = compression_encode_buffer(destinationBuffer, str.count, &sourceBuffer, str.count, nil, algorithm)
	if compressedSize == 0 {
			print("Encoding failed.")
	}*/
	
	// now upload
	uploadSample(str: str, type: "sample")
	
	// and save a copy to ~/Library/Application Support/appFilewall/samples/
	// so that use has a record of what has been uploaded
	if let sampleDir = getSampleDir() {
		let dateString = String(cString:get_date())
		let dateString2 = dateString.replacingOccurrences(of: " ", with: "_", options: .literal, range: nil)
		let sampleFile = sampleDir + "sample_" + dateString2
		print("uploaded sample of connections for ", app, " to ", Config.sampleURL, " and saved copy in ",sampleFile)
		do {
			try str.write(toFile: sampleFile, atomically: false, encoding: .utf8)
		} catch {
			print("WARNING: problem saving "+sampleFile+":"+error.localizedDescription)
		}
	}
	return "Sample uploaded for " + app
}


func sampleLogData(fname: String) {
	// upload a sample from the app connection log
	let path = String(cString:get_path())+fname
	var log_str : String = ""
	do {
		// read log.  it won't be larger than 5MB since we rotate it otherwise
		// so its ok to read into memory
		flush_logtxt()
		log_str = try String(contentsOfFile: path, encoding: String.Encoding.utf8)
	} catch {
		print("WARNING: sampleLogData() problem reading ",path,":", error.localizedDescription)
		return
	}
	let lines = log_str.components(separatedBy: "\n")
	if (lines.count == 0) { print("sampleLogData(): log empty"); return }

	// pick a line at random and choose that app,
	// so long as not a browser app
	var app : String = ""
	var count = 0
	let TRIES = 10
	repeat {
		let line = String(lines.randomElement() ?? "")
		let parts = line.split {$0 == "\t" }
		if (parts.count >= 2) {
			app = String(parts[1])
		} else { // likely an empty line
			app = ""
		}
		count = count + 1
	} while ((Config.browsers.contains(app) || (app.count==0)) && (count<TRIES))
	if ((Config.browsers.contains(app) || (app.count==0)) || (count == TRIES)) {
		print("WARNING: sampleLogData(): failed to sample app")
		// strange, we'll come back later
		return
	}
	let _ = sampleApp(fname: fname, lines: lines, app:app);
}

func doCheckForUpdates(quiet: Bool, autoUpdate: Bool) {
	// if quiet == true, don't show confirmation popup if there
	// are no updates.  if autoUpdate == true, don't ask user to
	// confirm update and don't show any associated popups/info
	// on progress of installing update
 print("doCheckForUpdates")
 let session = URLSession(configuration: .default)
 let task = session.dataTask(with: Config.updateCheckURL)
		{ data, response, error in
		if let error = error {
			quiet_error_popup(msg: "WARNING: error when checking for updates: " + error.localizedDescription, quiet: quiet)
			return
		}
		if let resp = response as? HTTPURLResponse {
		  if !(200...299).contains(resp.statusCode) {
		  	quiet_error_popup(msg: "WARNING: server error when checking for updates: "+String(resp.statusCode), quiet: quiet)
		  }
	 }
		if let data = data,
			 let dataString = String(data: data, encoding: .ascii) {
			 //print ("got data: ",dataString)
			 let lines = dataString.components(separatedBy:"\n")
			 let latest_version = lines[0].trimmingCharacters(in: .whitespacesAndNewlines)
			 let msg = lines[1].trimmingCharacters(in: .whitespacesAndNewlines)
			 guard let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
			  quiet_error_popup(msg: "WARNING: problem getting version from bundle when checking for updates", quiet: quiet)
				return
			 }
			 print("checking for updates.  our version=",version,", latest_version=",latest_version,", msg=",msg)
			 var result = "Up to date (current version "+version+" matches latest version "+latest_version+")"
			 var extra = ""
			 var new = false
			 if ((version != latest_version) || Config.testUpdates) {
				 result = "An update to version "+latest_version+" of appFirewall is available."
				 extra = "Download at <a href=\""+Config.updateURL+"\">"+Config.updateURL+"</a>"
				 new = true
			 }
			 print(extra)
			 if (msg != "<none>") {
				 result = result + "\n" + msg
			 }
			 if (!new) {
			 	if (quiet) { return } // up to date and don't want notification
			 	// show popup telling user no update needed
			 	DispatchQueue.main.async {
					let alert = NSAlert()
					alert.messageText = "Check for updates"
					alert.informativeText = result
					alert.alertStyle = .informational
					alert.runModal()
					return
				}
			 } else {
				 // display popup asking user they want to install update
			  	DispatchQueue.main.async {
					 updatePopup(msg:result, autoUpdate: autoUpdate)
			 	 }
			 }
		 }
	}
	task.resume()
	session.finishTasksAndInvalidate()
}

func updatePopup(msg: String, autoUpdate: Bool) {
	// give option to install, use custom view
	let storyboard = NSStoryboard(name:"Main", bundle:nil)
	let controller : UpdateInstallerViewController = storyboard.instantiateController(withIdentifier: "UpdateInstallerViewController") as! UpdateInstallerViewController
	controller.start(autoUpdate: autoUpdate, msg: msg)
}

func runCmd(cmd: String, args: [String])->String {
	let task = Process();
	task.launchPath = cmd
	task.arguments = args
	let pipe = Pipe()
	task.standardOutput = pipe
	task.standardError = pipe
	task.launch()
	let resp = pipe.fileHandleForReading.readDataToEndOfFile()
	task.waitUntilExit()
	// resp is a Data object i.e. a bytebuffer
	// so convert to string
	let resp_str = (String(data: resp, encoding: .utf8) ?? "-1").trimmingCharacters(in: .whitespacesAndNewlines)
	return resp_str
}

func getFileXattribs(file:String)->[String] {

	/*
	// this is nicer but doesn't return all of the extended attributes
	var names:[String] = []
	if let attr = try? FileManager.default.attributesOfItem(atPath:file) as NSDictionary {
		if let xattribs = attr["NSFileExtendedAttributes"] as? NSDictionary {
			for (key,_) in xattribs {
				if let str = key as? String {
					names.append(str)
				}
			}
		}
	}
	return names*/

	let bufLength = listxattr(file, nil, 0, 0)
	if bufLength != -1 {
		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: bufLength)
		if listxattr(file, buf, bufLength, 0) != -1 {
			if var names = NSString(bytes: buf, length: bufLength, encoding: String.Encoding.utf8.rawValue)?.components(separatedBy: "\0") {
				names.removeLast()
				return names
			}
		}
	}
	return []
	
}

func getSecuritySettings() {
	var str: String = ""
	str = "#OS version:\n"+ProcessInfo.processInfo.operatingSystemVersionString+"\n"
	str = str + "#Locale:\n"+Locale.current.identifier+"\n"
	str = str + NSTimeZone.local.identifier+"\n"
	str = str + NSTimeZone.system.identifier+"\n"
	str = str+"#SIP enabled:\n"
	str = str + runCmd(cmd:"/usr/bin/csrutil",args:["status"])+"\n"
	str = str+"#Filevault enabled:\n"+runCmd(cmd:"/usr/bin/fdesetup",args:["status"])+"\n"
	str = str+"#Gatekeeper enabled:\n"+runCmd(cmd:"/usr/sbin/spctl",args:["--status"])+"\n"
	str = str+"#Application firewall:\n"
	str = str + runCmd(cmd:"/usr/libexec/ApplicationFirewall/socketfilterfw",args:["--getglobalstate", "--getallowsigned", "--getstealthmode", "--listapps"])
	str = str + "\n"
	let files = try? FileManager.default.contentsOfDirectory(atPath:"/Applications")
	str = str+"#Quarantine:"+"\n"
	for file in files ?? [""] {
		str = str+"##xattr "+file+"\n"
		//str = str+runCmd(cmd:"/usr/bin/xattr", args:["/Applications/"+file])+"\n"
		str = str + (getFileXattribs(file:"/Applications/"+file)).joined(separator:",")+"\n"
		//str = str+"##spctl "+file+"\n"
		//str = str+runCmd(cmd:"/usr/sbin/spctl", args:["--assess", "-vvvv", "--continue", "/Applications/"+file])+"\n"
	}
	//print(str)
	uploadSample(str: str, type: "settings")
	if let sampleDir = getSampleDir() {
		let dateString = String(cString:get_date())
		let dateString2 = dateString.replacingOccurrences(of: " ", with: "_", options: .literal, range: nil)
		let sampleFile = sampleDir + "security_settings_" + dateString2
		print("uploaded security settings to ", Config.sampleURL, " and saved copy in ",sampleFile)
		do {
			try str.write(toFile: sampleFile, atomically: false, encoding: .utf8)
		} catch {
			print("WARNING: problem saving "+sampleFile+":"+error.localizedDescription)
		}
	}
}

func getIntstalledApps()->[String] {
	// returns a list of app names from /Applications.  doesn't include
	// embedded apps e.g. Google Chrome Helper (which is embedded inside
	// Google Chrome and its metadata isn't tagged as an app)
	
	// to do ? could also use NSMetadataQuery but it seems much nastier
	let output = runCmd(cmd:"/usr/bin/mdfind",args:["kMDItemContentTypeTree=com.apple.application-bundle","-onlyin","/Applications"])
	//print(output)
	var apps: [String] = []
	for item in output.components(separatedBy:"\n") {
		//if let b = Bundle(path: item) {
			//print(b.infoDictionary?["CFBundleName"], " ", p.lastPathComponent)
		//}
		if let p = Bundle(path: item)?.executableURL?.lastPathComponent {
			apps.append(p)
		}
	}
	return apps
}

func pgrep(Name: String)->Int {
	// return whether any running processing match Name
	let res = Int(find_proc(Name))
	print("pgrep for ",Name,": ",res)
	return res
	
	/*import AppKit
	let res = NSWorkspace.shared.runningApplications
	var count = 0
	for r in res {
		print(r.localizedName," ",r.processIdentifier)
		if (r.localizedName == Name) { print("match"); count += 1 }
	}
	print(count)
	return count*/
}

func unitTesting()->Bool {
	//return UserDefaults.standard.bool(forKey: "testing")
	return (NSClassFromString("XCTest") != nil)
	//return ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
}
