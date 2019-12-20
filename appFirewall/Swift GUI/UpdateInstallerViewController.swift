//
//  installUpdate.swift
//  appFirewall
//
//  Created by Doug Leith on 19/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Foundation
import Cocoa

// to do:
// Config.enable
// sourceforge vs github ?
// allow timed update
// add user pref to allow timed update

class UpdateInstallerViewController: NSViewController {
	
	let appFile = "appFirewall.app" // name of app inside DMG
	let hdiutil = "/usr/bin/hdiutil"
	var msg: String = ""
	var autoUpdate: Bool = false
	var window: NSWindow?
	var wc: NSWindowController?
	
	// popup UI elements
	@IBOutlet weak var msgField: NSTextField?
	@IBOutlet weak var statusField: NSTextField?
	@IBAction func okButton(_ sender: NSButton) {
		// user has cancelled the update
		sender.window?.close()
	}
	@IBAction func installButton(_ sender: NSButton) {
		// user has agreed to install the update
		sender.isEnabled  = false // stop user pressing button again
		downloadAndInstallUpdate()
	}
	
	// open popup if needed, else leave closed
	func start(autoUpdate: Bool, msg: String) {
		self.autoUpdate = autoUpdate
		if (autoUpdate) {
			// no need to ask user whether they want to update,
			// and no need to show popup/info on progress installing update
			downloadAndInstallUpdate()
		} else {
			// if autoUpdate then fall back to
			// displaying popup and asking user if we should do
			// update
			self.msg = msg // we'll display this once popup view has loaded
			window = NSWindow(contentViewController: self)
			window?.styleMask.remove(.miniaturizable)
			window?.styleMask.remove(.resizable) // fixed size
			wc = NSWindowController(window: window)
			wc?.showWindow(self)
		}
	}
	
	override func viewDidLoad() {
		// popup window to ask user if they want to install update
		// has loaded
		super.viewDidLoad()
		msgField?.stringValue = msg
		msgField?.sizeToFit()
		statusField?.stringValue = ""
	}
	
	func showPopupMsg(msg: String) {
		// update the information message shown in popup
		print(msg) // in log
		if (!autoUpdate) { // no popup
			statusField?.stringValue = msg
			statusField?.sizeToFit()
		}
	}
	
	func downloadAndInstallUpdate() {
		// if autoUpdate == true, there is no popup window and no need
		// to show progress info to user, otherwise the popup window
		// is being displayed and we need to update it.  showPopupMsg()
		// is the main place that autoUpdate affects
		
		// start by downloading the update DMG, once finished will install
		let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
		guard let url = URL(string: Config.updateURL) else { return }
		session.downloadTask(with: url).resume()
		showPopupMsg(msg:"Download started ...")
		session.finishTasksAndInvalidate()
	}
		
	func checkSignature(bundle: String)->Bool {
		// check that downloaded DMG has reasonable signature
		var staticCode: SecStaticCode?
		let result = SecStaticCodeCreateWithPath(URL(fileURLWithPath:bundle) as CFURL, SecCSFlags.init(rawValue: 0), &staticCode)
		if (result != noErr) {
			print("WARNING: problem getting code ref: ", result);
			return false
		}
		var req : SecRequirement?
		let req_str = "identifier com.leith.appFirewall and anchor apple generic"
		SecRequirementCreateWithString(req_str as CFString, [], &req);
		// check signature against embedded requirements
		guard staticCode != nil else { print("WARNING: problem getting code ref"); return false }
		let status = SecStaticCodeCheckValidity(staticCode!, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), req)
		if (status != errSecSuccess) {
			let flags = SecCSFlags(rawValue: kSecCSInternalInformation
				| kSecCSSigningInformation
				| kSecCSRequirementInformation
				| kSecCSInternalInformation)
			var api: CFDictionary?
			let status2 = SecCodeCopySigningInformation(staticCode!, flags, &api)
			if (status2 != errSecSuccess) { print("DMG signature invalid, but problem getting further details"); return false }
			let api2 = api as NSDictionary?
			print("DMG signature invalid: identifier ", api2?["identifier"] as Any)
			return false
		}
		return true
	}
	
	func unmount(mountPoint: String) {
		// unmount DMG.  called when errors encountered, so factor
		// out as its own function
		let unmountTask = Process()
		unmountTask.launchPath = hdiutil
		unmountTask.arguments=["detach", mountPoint,"-force"]
		print("starting hdiutil to unmount DMG")
		unmountTask.launch()
		unmountTask.waitUntilExit()
		print("done")
		//print(unmountTask.terminationStatus, unmountTask.terminationReason)
		if (unmountTask.terminationStatus != 0) {
			print("WARNING: hdiutil umount of DMG failed: ",unmountTask.terminationReason)
		}
	}
	
	func updateApp(dmgURL: URL, appPath: String) {
		// carry out the actual app updating
		
		DispatchQueue.main.async { self.showPopupMsg(msg: "Mounting DMG ...") }
		
		let mountPoint = "/Volumes/"+UUID().uuidString
		print(mountPoint)
		
		// mount DMG
		let mountTask = Process()
		let stdin = Pipe()
		mountTask.launchPath = hdiutil
		mountTask.arguments = ["attach", dmgURL.path, "-mountpoint", mountPoint,"-nobrowse","-noautoopen"]
		mountTask.standardInput = stdin
		print("starting hdiutil to mount DMG")
		mountTask.launch()
		let handle = stdin.fileHandleForWriting
		let yes = "yes\n".data(using: .utf8)!
		handle.write(yes)
		mountTask.waitUntilExit()
		print("done")
		if (mountTask.terminationStatus != 0) {
			let msg = "Problem when trying to install update, hdiutil mount of DMG failed"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}

		// check contents look sane
		DispatchQueue.main.async { self.showPopupMsg(msg: "Extracting app ...") }
		if !FileManager.default.fileExists(atPath: mountPoint+"/"+appFile) {
			unmount(mountPoint:mountPoint)
			let msg = "Problem when trying to install update, couldn't find "+appFile+" in DMG"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}
		if !checkSignature(bundle: mountPoint+"/"+appFile) {
			let msg = "Problem when trying to install update, signature invalid for "+appFile+" in DMG"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}

		// copy to Applications folder
		DispatchQueue.main.async { self.showPopupMsg(msg: "Updating app ...") }
		do {
			let tempPath = NSTemporaryDirectory()
			print("copying DMG contents to temp staging folder ",tempPath)
			try? FileManager.default.removeItem(atPath: tempPath+"/"+appFile)
			try FileManager.default.copyItem(atPath: mountPoint+"/"+appFile, toPath: tempPath+"/"+appFile)
			//print(try FileManager.default.attributesOfItem(atPath:tempPath+"/"+appFile))
			
			if (Config.enableUpdates == 1) {
				print("now copying contents of staging folder ",tempPath, " to final folder ", appPath)
				_ = try FileManager.default.replaceItemAt(URL(fileURLWithPath:appPath), withItemAt: URL(fileURLWithPath: tempPath+"/"+appFile))
			}
		} catch {
			let msg = "Problem when trying to install update, couldn't copy updated app into final location: "+error.localizedDescription
			unmount(mountPoint:mountPoint)
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}
		
		// unmount DMG
		unmount(mountPoint:mountPoint)
		
		// and now relaunch app
		if (Config.enableUpdates == 1) {
			DispatchQueue.main.async { self.showPopupMsg(msg: "Updated, restarting.") }
			restart_app()
		} else {
			window?.close()
		}
	}
}

extension UpdateInstallerViewController: URLSessionDownloadDelegate {

	func urlSession(_ session: URLSession,
									downloadTask task: URLSessionDownloadTask,
									didWriteData bytesWritten: Int64,
									totalBytesWritten: Int64,
									totalBytesExpectedToWrite: Int64) {
		var progress : String
		if (totalBytesExpectedToWrite>0) {
			progress = String(Int(100.0*Float(totalBytesWritten)/Float(totalBytesExpectedToWrite)))+"%"
		} else {
			progress = "..."
		}
		DispatchQueue.main.async {
			self.showPopupMsg(msg: "Downloading "+progress)
		}
	}
	
	func urlSession(_ session: URLSession,
									downloadTask task: URLSessionDownloadTask,
									didFinishDownloadingTo fileURL: URL) {
		// catch server-side errors
		guard let resp = task.response as? HTTPURLResponse else {
			let msg="WARNING: problem in installUpdate urlSession getting HTTP response"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}
		let statusCode = resp.statusCode
		//print("status:", statusCode)
		let url = String(task.originalRequest?.url?.absoluteString ?? "<unknown>")
		if (statusCode != 200) {
			let msg = "Problem downloading "+url+": "+HTTPURLResponse.localizedString(forStatusCode: statusCode)+"(HTTP status:"+String(statusCode)+")"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
		} else {
			print("Successully downloaded ",url)
			updateApp(dmgURL: fileURL, appPath: Bundle.main.bundlePath)
		}
	}
	
	func urlSession(_ session: URLSession,
									task: URLSessionTask,
									didCompleteWithError error: Error?) {
		
		if (error == nil) { return } // nothing of interest
		
		// client side error (e.g. couldn't connect)
		let url = String(task.originalRequest?.url?.absoluteString ?? "<unknown>")
		let msg = "Problem downloading "+url+": "+(error?.localizedDescription ?? "<unknown>")
		DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
	}
}
