//
//  AppDelegate.swift
//  appFirewall-loginLaunch
//
//  Created by Doug Leith on 23/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa
import os

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

	func applicationDidFinishLaunching(_ aNotification: Notification) {
		let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as! String
		os_log("com.leith.appFirewall-autoLaunch (version %{public}s) started", version)
		let runningApps = NSWorkspace.shared.runningApplications
		let isRunning = runningApps.contains {
			$0.bundleIdentifier == "com.leith.appFirewall"
		}
		if (isRunning) {
			os_log("running is: true")
		} else {
			os_log("running is: false")
		}

		if !isRunning {
			var path = Bundle.main.bundlePath as NSString
			for _ in 1...4 {
					path = path.deletingLastPathComponent as NSString
			}
			os_log("path %{public}s",path)
			NSWorkspace.shared.launchApplication(path as String)
			/*let task = Process()
			task.launchPath = "/usr/bin/open"
			task.arguments = ["/Applications/appFirewall.app"]
			task.launch()
			*/
			os_log("com.leith.appFirewall started")
		}
		sleep(15) // otherwise launchd may think helper has crashed and relaunch it
		exit(EXIT_SUCCESS)
	}
}

