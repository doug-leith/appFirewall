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
func setup_sigterm_handler() {
	// if a C routine fatally fails it raises a SIGCHLD signal
	// and we catch it here to raise an popup to inform user
	// and exit gracefully
	let handler: @convention(c) (Int32) -> () = { sig in
		// handle the signal
		exit_popup(msg:String(cString: get_error_msg()))
	}
	var action = sigaction(__sigaction_u: unsafeBitCast(handler, to: __sigaction_u.self),
												sa_mask: 0,
												sa_flags: 0)
	sigaction(SIGCHLD, &action, nil)
}

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

func log_rotate(logName: String) {
	// rotate human readable log file if getting too large
	let path = String(cString: get_path())
	let logfile = path + "/" + logName
	var fileSize : UInt64 = 0
	do {
		let attr = try FileManager.default.attributesOfItem(atPath: logfile)
		fileSize = attr[FileAttributeKey.size] as! UInt64
	} catch {
			print("Problem rotating log "+logName+": "+error.localizedDescription)
	}
	if (fileSize > 100000000) { // 100M
		// rotate
		print("Rotating log "+logfile)
		do {
			try FileManager.default.removeItem(atPath:logfile+".0")
		} catch {
				print("Rotating log "+logName+": "+error.localizedDescription)
		}
		do {
			try FileManager.default.moveItem(atPath:logfile, toPath: logfile+".0")
			} catch {
					print("Rotating log "+logName+": "+error.localizedDescription)
			}
	}
}

// -------------------------------------
// UI Helpers

func exit_popup(msg: String) {
	print(msg)
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "OK")
	alert.runModal()
	exit(1)
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
