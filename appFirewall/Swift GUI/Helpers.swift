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
	// create ~/Library/Application Support/appFirewall directory if
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
	save_log()
	save_blocklist(); save_whitelist()
	save_dns_cache(); save_dns_conn_list()
}

func load_state() {
	load_log();
	load_blocklist(); load_whitelist()
	load_dns_cache(); load_dns_conn_list()
}

// -------------------------------------
// UI Helpers

func exit_popup(msg: String, force:Int) {
	print(msg)
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "Restart")
	alert.addButton(withTitle: "OK")
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
		exit(1)
	}
}

func restart_app() {
	let url = URL(fileURLWithPath: Bundle.main.resourcePath!)
	let path = url.deletingLastPathComponent().deletingLastPathComponent().absoluteString
	let task = Process()
	task.launchPath = "/usr/bin/open"
	task.arguments = [path]
	task.launch()
	exit(0)
}

func error_popup(msg: String) {
	print(msg)
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "OK")
	alert.runModal()
}

func update_popup(msg: String, extra: String) {
	//print(msg)
	let alert = NSAlert()
	alert.messageText = "Check for updates"
	alert.informativeText = msg
	let h = Data(extra.utf8)
	if let html = try? NSMutableAttributedString(data:h, options: [.documentType: NSAttributedString.DocumentType.html], documentAttributes: nil) {
		//let v = HyperlinkTextView(frame: NSMakeRect(0,0,300,40))
		let v = HyperlinkTextView(frame: html.boundingRect(with: NSSize(width: 300, height: 40)))
		v.isEditable = false; v.drawsBackground = false; //v.isBezeled = false
		v.textStorage!.append(html)
		alert.accessoryView = v
	}
	alert.alertStyle = .informational
	alert.addButton(withTitle: "OK")
	alert.runModal()
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
