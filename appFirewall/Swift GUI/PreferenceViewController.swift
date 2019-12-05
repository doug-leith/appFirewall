//
//  PreferenceViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class PreferenceViewController: NSViewController {

	@IBOutlet weak var tableView: NSTableView?
	@IBOutlet weak var tableSelectedView: NSTableView?
	
	var lists_lastUpdated : String = ""
	var EnabledLists : [String] = []
	var AvailableLists : [String] = []
	var changed : Bool = false
	var timer : Timer = Timer()
	var downloadStartTime :  Double = 0
	var downloadsInProgress : [Int] = []
	var downloadsErrors : [String] = []
	
	override func viewDidLoad() {
		super.viewDidLoad()
		// Do view setup here.
		tableView!.delegate = self as NSTableViewDelegate
		tableView!.dataSource = self as NSTableViewDataSource
		tableSelectedView!.delegate = self as NSTableViewDelegate
		tableSelectedView!.dataSource = self as NSTableViewDataSource
		
		lists_lastUpdated = UserDefaults.standard.string(forKey: "lists_lastUpdated") ?? String("")
		refreshLabel?.stringValue = "(Last updated:  "+lists_lastUpdated+")"
		timer = Timer.scheduledTimer(timeInterval: Config.viewRefreshTime, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
	}
  
  func updateAvailableLists() {
		AvailableLists = []
		for item in Config.hostNameLists{
			guard let n = item["Name"] else { print("WARNING: problem in preferenceView empty name in host list on update"); continue };
			guard EnabledLists.firstIndex(of: n) == nil else { continue }
			AvailableLists.append(n);
		}
	}
	
	func load_hostlists() {
		// called by AppDelegate on application startup, and also by self
		// on changes to set of enabled lists
		
		// set default host list(s) to use
		UserDefaults.standard.register(defaults: Config.defaultNameList)
		// reload enabled lists, persistent across runs of app
		// and wil default to above if not previously set
		EnabledLists = UserDefaults.standard.array(forKey: "host_lists") as? [String] ?? []
		updateAvailableLists()
		
		// update the host name files used, and reload,
		// we fall back to files distributed by app
		init_hosts_list();
		let filePath = String(cString:get_path())
		let backupPath = Bundle.main.resourcePath ?? "./"
		var n = String("")
		for item in Config.hostNameLists {
			guard let nn = item["Name"] else { print("WARNING: problem in preferenceView empty name in host list");  continue };
			guard EnabledLists.firstIndex(of: nn) != nil else { continue };
			guard let fname = item["File"] else { continue };
			print("adding ", filePath+fname)
			if (item["Type"]=="Hostlist") {
				// read in file and adds to hosts list table
				n=filePath+fname
				if (load_hostsfile(n)<0) {
					n=backupPath+"/BlackLists/"+fname
					print("Falling back to loading from ",n)
					load_hostsfile(n)
				}
			} else if (item["Type"]=="Blocklist") {
				// read in file and adds to hosts list table
				n=filePath+fname
				if (load_blocklistfile(n)<0){
					n=backupPath+"/BlackLists/"+fname
					print("Falling back to loading from ",n)
					load_blocklistfile(n)
				}
			}
			lists_lastUpdated = String(cString:get_file_modify_time(n))
			print("from file: last updated=",lists_lastUpdated)
			UserDefaults.standard.set(lists_lastUpdated, forKey: "lists_lastUpdated")
		}
	}
	
	override func viewWillDisappear() {
		// window is closing, save state
		super.viewWillDisappear()
		if (changed) {
			load_hostlists()
			changed = false
		}
		timer.invalidate()
	}

	@IBAction func AddButton(_ sender: Any) {
		guard let row = tableView?.selectedRow else {print("WARNING: problem in preferenceView addButton getting row");  return}
		if (row<0 || row > Config.hostNameLists.count) { return }
		
		for item in EnabledLists {
			if (item == AvailableLists[row]) {
				// already enabled, ignore
				return
			}
		}
		EnabledLists.append(AvailableLists[row])
		UserDefaults.standard.set(EnabledLists, forKey: "host_lists")
		updateAvailableLists()
		tableSelectedView?.reloadData()
		tableView?.reloadData()
		changed = true
	}
	
	@IBAction func RemoveButton(_ sender: Any) {
		guard let row = tableSelectedView?.selectedRow else {print("WARNING: problem in preferenceView removeButton getting row"); return}
		EnabledLists.remove(at: row)
		UserDefaults.standard.set(EnabledLists, forKey: "host_lists")
		updateAvailableLists()
		tableSelectedView?.reloadData()
		tableView?.reloadData()
		changed = true
	}
	
	@objc func refresh() {
		if (!isViewLoaded) { return }
		
		refreshLabel?.stringValue = "(Last updated:  "+lists_lastUpdated+")"
		let elapsedTime = Date().timeIntervalSinceReferenceDate - downloadStartTime
		if ((downloadsInProgress.count != 0) && (elapsedTime>10.0)) {
			// one or more downloads is stuck, tell user about any errors anyway and renable button
			reportDownloadErrors()
		}
	}
	
	@IBOutlet weak var refreshLabel: NSTextField?
	
	@IBOutlet weak var refreshButton: NSButton?
	
	@IBAction func clickRefreshButton(_ sender: NSButton) {
		let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
		refreshButton?.isEnabled = false
		downloadStartTime = Date().timeIntervalSinceReferenceDate
		for (index, item) in Config.hostNameLists.enumerated() {
			let url_string = item["URL"] ?? ""
			if (url_string.count < 5) { continue; }
			let fname = item["File"] ?? ""
			if (fname.count == 0){ continue; }
			
			guard let url = URL(string: url_string) else {print("WARNING: problem in preferenceView getting url");  return}
			let downloadTask = session.downloadTask(with: url)
			downloadTask.taskDescription = String(index)
			downloadTask.resume()
			print("Download started for ", url)
			downloadsInProgress.append(index)
			//return
		}
		session.finishTasksAndInvalidate()
	}
}

extension PreferenceViewController: URLSessionDownloadDelegate {

	func updateDownloadProgess(index: Int, progress: String) {
		if (!isViewLoaded) { return }
		
		// let's find where list is located
		let name = Config.hostNameLists[index]["Name"]
		var row: Int = -1
		for (i, item) in EnabledLists.enumerated()  {
			if (item == name) {
				row = i
				break;
			}
		}
		if (row >= 0) {
			guard let cell = tableSelectedView?.view(atColumn:0, row:row, makeIfNecessary: true) as? NSTableCellView else {print("WARNING: problem in preferenceView updateDownloadProgess getting tableSelectedView cell"); return}
			cell.textField?.stringValue = EnabledLists[row]+" "+progress
		} else {
			var row:  Int = -1
			for (i, item) in AvailableLists.enumerated()  {
				if (item == name) {
					row = i
					break;
				}
			}
			if (row < 0) { // shouldn't happen
				print("updateDownloadProgess() problem finding list")
				return
			}
			guard let cell = tableView?.view(atColumn:0, row:row, makeIfNecessary: true) as? NSTableCellView else {print("WARNING: problem in preferenceView updateDownloadProgess getting tableView cell");return}
			cell.textField?.stringValue = AvailableLists[row]+" "+String(progress)
		}
	}
	
	func getIndex(task: URLSessionTask) -> (Int,Int) {
		guard let index = Int(task.taskDescription ?? "-1") else {print("WARNING: problem in preferenceView getIndex getting index"); return (-1,-1)}
		if (index<0) { // shouldn't happen
			print("Problem with download task, taskDescription:",task.taskDescription ?? "")
		}
		// update list of downloads in progress
		let loc = downloadsInProgress.firstIndex(of:index)
		if (loc == nil) { // shouldn't happen
			print("Problem with download task, can't find in downloadsInProgress:", index, downloadsInProgress)
		}
		return (index, loc ?? -1)
	}

	func reportDownloadErrors() {
		DispatchQueue.main.async {
			if (self.downloadsErrors.count > 0)  {
				var msgs : String = ""
				for msg in self.downloadsErrors {
					msgs += msg
				}
				self.downloadsErrors.removeAll() // only show errors once
				error_popup(msg: msgs)
			}
			// it may happen that view is closed by the time we get here
			if (!self.isViewLoaded) { return }
			
			self.refreshButton?.isEnabled = true
			self.tableSelectedView?.reloadData()
			self.tableView?.reloadData()
		}
	}
	
	func urlSession(_ session: URLSession,
									downloadTask task: URLSessionDownloadTask,
									didWriteData bytesWritten: Int64,
									totalBytesWritten: Int64,
									totalBytesExpectedToWrite: Int64) {
		let (index, _) = getIndex(task: task)
		if (index < 0) { return }
		var progress : String
		if (totalBytesExpectedToWrite>0) {
		 	progress = String(Int(100.0*Float(totalBytesWritten)/Float(totalBytesExpectedToWrite)))+"%"
		} else {
			progress = "..."
		}
		DispatchQueue.main.async {
			self.updateDownloadProgess(index: index, progress: progress)
		}
	}
		
	func urlSession(_ session: URLSession,
									downloadTask task: URLSessionDownloadTask,
									didFinishDownloadingTo fileURL: URL) {
		// get which list we've downloaded
		let (index, loc) = getIndex(task: task)
		if (index < 0) { return }
		if (loc >= 0 ) { downloadsInProgress.remove(at: loc) }

		// catch server-side errors
		guard let resp = task.response as? HTTPURLResponse else {print("WARNING: problem in preferenceView urlSession getting HTTP response");  return}
		let statusCode = resp.statusCode
		//print("status:", statusCode)
		let url = String(task.originalRequest?.url?.absoluteString ?? "<unknown>")
		if (statusCode != 200) {
			let msg = "Problem downloading "+url+": "+HTTPURLResponse.localizedString(forStatusCode: statusCode)+"(HTTP status:"+String(statusCode)+")"
			downloadsErrors.append(msg)
			print(msg)
		} else {
			guard let fname = Config.hostNameLists[index]["File"] else {print("WARNING: problem in preferenceView urlSession getting filename");  return}
			let path = String(cString:get_path())+fname
			do {
				try FileManager.default.removeItem(atPath: path+".0")
			} catch {}
			do {
				try FileManager.default.moveItem(atPath: path, toPath: path+".0")
			} catch {}
			do {
				try FileManager.default.moveItem(atPath: fileURL.path, toPath: path)
			} catch {
				print ("Error moving ",fileURL," to ",path,":", error)
			}
			self.lists_lastUpdated = String(cString:get_file_modify_time(path))
			print("Successully downloaded ",url,", t=",self.lists_lastUpdated)
			UserDefaults.standard.set(self.lists_lastUpdated, forKey: "lists_lastUpdated")
		}
		// we batch errors into a single popup
		if (downloadsInProgress.count == 0) {
			reportDownloadErrors()
		}
	}
	
	func urlSession(_ session: URLSession,
									task: URLSessionTask,
									didCompleteWithError error: Error?) {
									
		if (error == nil) { return } // nothing of interest
		
		let (index, loc) = getIndex(task: task)
		if (index < 0) { return }
		if (loc >= 0 ) { downloadsInProgress.remove(at: loc) }

		// client side error (e.g. couldn't connect)
		let url = String(task.originalRequest?.url?.absoluteString ?? "<unknown>")
		let msg = "Problem downloading "+url+": "+(error?.localizedDescription ?? "<unknown>")
		print(msg)
		downloadsErrors.append(msg)
		// we batch errors into a single popup
		if (downloadsInProgress.count == 0) {
			reportDownloadErrors()
		}
	}
}

extension PreferenceViewController: NSTableViewDataSource {
	func numberOfRows(in tView: NSTableView) -> Int {
		if (tView == tableView) {
			return AvailableLists.count
		} else {
			return EnabledLists.count
		}
	}
}

extension PreferenceViewController: NSTableViewDelegate {
	
	func tableView(_ tView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		if (!self.isViewLoaded) { return nil }
		
		if (tView == tableView) {
			let cellId = NSUserInterfaceItemIdentifier(rawValue: "HostListCell")
			
			guard let cell = tableView?.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in preferenceView tableView making cell"); return nil}
			cell.textField?.stringValue = AvailableLists[row]
			var tip = ""
			for item in Config.hostNameLists {
				guard let n = item["Name"] else {print("WARNING: in preferenceView empty name in list"); continue}
				if (n == AvailableLists[row]) {
						tip = item["Tip"] ?? ""
						tip += "\nURL:" + (item["URL"] ?? "")
						break
				}
			}
			cell.textField?.toolTip = tip

			return cell
		} else {
			let cellId = NSUserInterfaceItemIdentifier(rawValue: "EnabledListCell")
			
			guard let cell = tableSelectedView?.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in preferenceView making cell"); return nil}
			cell.textField?.stringValue = EnabledLists[row]
			var tip = ""
			for item in Config.hostNameLists {
				guard let n = item["Name"] else {print("WARNING: problem in preferenceView empty name in host list");  continue}
				if (n == EnabledLists[row]) {
							tip = item["Tip"] ?? ""
						tip += "\nURL:" + (item["URL"] ?? "")
					break
				}
			}
			cell.textField?.toolTip = tip

			return cell
		}
	}
}

