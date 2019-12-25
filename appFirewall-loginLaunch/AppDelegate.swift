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
		os_log("com.leith.appFirewall-autoLaunch started")
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
			let task = Process()
			task.launchPath = "/usr/bin/open"
			task.arguments = ["/Applications/appFirewall.app"]
			task.launch()
			os_log("com.leith.appFirewall-autoLaunch: com.leith.appFirewall started")
		}
		sleep(15) // otherwise launchd may think helper has crashed and relaunch it
		exit(1)
	}
}

