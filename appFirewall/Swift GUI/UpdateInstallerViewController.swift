//
//  installUpdate.swift
//  appFirewall
//
//  Created by Doug Leith on 19/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Foundation
import Cocoa

func doCheckForUpdates() {
 let session = URLSession(configuration: .default)
 let task = session.dataTask(with: Config.updateCheckURL)
		{ data, response, error in
		if let error = error {
				DispatchQueue.main.async {
					error_popup(msg:"WARNING: error when checking for updates: \(error)")
				}
				return
		}
		if let resp = response as? HTTPURLResponse {
		 if !(200...299).contains(resp.statusCode) {
			 DispatchQueue.main.async { error_popup(msg: "WARNING: server error when checking for updates: "+String(resp.statusCode)) }
		 }
	 }
		if let data = data,
			 let dataString = String(data: data, encoding: .ascii) {
			 //print ("got data: ",dataString)
			 let lines = dataString.components(separatedBy:"\n")
			 let latest_version = lines[0].trimmingCharacters(in: .whitespacesAndNewlines)
			 let msg = lines[1].trimmingCharacters(in: .whitespacesAndNewlines)
			 guard let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
				DispatchQueue.main.async {
					error_popup(msg: "WARNING: problem getting version from bundle when checking for updates")
				}
				return
			 }
			 print("checking for updates.  our version=",version,", latest_version=",latest_version,", msg=",msg)
			 var result = "Up to date (current version "+version+" matches latest version "+latest_version+")"
			 var extra = ""
			 var new = false
			 if (version != latest_version) {
				 result = "An update to version "+latest_version+" is available."
				 extra = "Download at <a href=\""+Config.updateURL+"\">"+Config.updateURL+"</a>"
				 new = true
			 }
			 print(extra)
			 if (msg != "<none>") {
				 result = result + "\n" + msg
			 }
			 DispatchQueue.main.async {
				 updatePopup(msg:result, extra:extra, new:new)
			 }
		 }
}
task.resume()
session.finishTasksAndInvalidate()
}

func updatePopup(msg: String, extra: String, new: Bool) {
	//called to display outcome of checking for updates
	// - allows user to then download and update if appropriate
	if (!new) { // just use an alert popup
		let alert = NSAlert()
		alert.messageText = "Check for updates"
		alert.informativeText = msg
		alert.alertStyle = .informational
		alert.runModal()
		return
	} else { // give option to install, use custom view
		let storyboard = NSStoryboard(name:"Main", bundle:nil)
		let controller : UpdateInstallerViewController = storyboard.instantiateController(withIdentifier: "UpdateInstallerViewController") as! UpdateInstallerViewController
		controller.msg = msg
		let myWindow = NSWindow(contentViewController: controller)
		myWindow.styleMask.remove(.miniaturizable)
		myWindow.styleMask.remove(.resizable) // fixed size
		let vc = NSWindowController(window: myWindow)
		vc.showWindow(controller)
	}
}

class UpdateInstallerViewController: NSViewController {
	
	//static let shared = UpdateInstallerViewController()
	let appFile = "appFirewall.app" // name of app inside DMG
	let hdiutil = "/usr/bin/hdiutil"
	var msg: String = ""
		
	@IBOutlet weak var msgField: NSTextField!
	
	@IBOutlet weak var statusField: NSTextField!
		
	@IBAction func okButton(_ sender: NSButton) {
		sender.window?.close()
	}
	
	@IBAction func installButton(_ sender: NSButton) {
		sender.isEnabled  = false // stop user pressing button again
		downloadAndInstallUpdate()
	}
	
	override func viewDidLoad() {
		print("updateinstaller view loaded")
		super.viewDidLoad()
		msgField.stringValue = msg
		msgField.sizeToFit()
		statusField.stringValue = ""
}
	
	func showPopupMsg(msg: String) {
		print(msg) // in log
		statusField.stringValue = msg
		statusField.sizeToFit()
	}
	
	func downloadAndInstallUpdate() {
		
		let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
		guard let url = URL(string: Config.updateURL) else { return }
		session.downloadTask(with: url).resume()
		showPopupMsg(msg:"Download started ...")
		session.finishTasksAndInvalidate()
	}
		
	func checkSignature(bundle: String)->Bool {
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
		// unmount DMG
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
		//handle.closeFile()
		mountTask.waitUntilExit()
		print("done")
		//print(mountTask.terminationStatus, mountTask.terminationReason)
		if (mountTask.terminationStatus != 0) {
			let msg = "Problem when trying to install update, hdiutil mount of DMG failed"
			DispatchQueue.main.async { self.showPopupMsg(msg:msg) }
			return
		}

		DispatchQueue.main.async { self.showPopupMsg(msg: "Extracting app ...") }

		// check contents look sane
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

		DispatchQueue.main.async { self.showPopupMsg(msg: "Updating app ...") }

		// copy to Applications folder
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
		
		DispatchQueue.main.async { self.showPopupMsg(msg: "Updated, restarting.") }
		// and now relaunch app
		if (Config.enableUpdates == 1) {
			restart_app()
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
