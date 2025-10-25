# AppFirewall

A free, fully open-source application firewall for macOS 10.13 High Sierra and later.  Allows real-time monitoring of network connections being made by applications, and blocking/allowing of these per app by user.  Supports use of hostname lists ([Energized Blu](https://energized.pro/) etc) to block known tracker and advertising domains for all apps.  Also allows blocking of all network connections for specified apps, blocking of all connections except for specified whitelisted connections, use of pre-configured lists of connections per app to allow/block etc.   Allows blocking of [Google QUIC](https://en.wikipedia.org/wiki/QUIC) traffic.  Can encrypt your DNS traffic using [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS).  

![Screenshot](https://github.com/doug-leith/appFirewall/raw/master/Screenshot.png)

## Getting Started

* [Download the .dmg](https://github.com/doug-leith/appFirewall/raw/master/latest%20release/appFirewall.dmg) and open it.  
* Drag the appFirewall icon into your Applications folder and click on it to start, there's nothing more to it.

## How It Works

The firewall sniffs packets to detect TCP network connections. 
  
* On spotting a new connection it tries to find the app which is the source of the connection (you can try this yourself using the command "lsof -i | grep -i tcp").   
* It also tries to resolve the raw IP address from the connection to a domain name, e.g. www.google-analytics.com, by sniffing DNS response packets.  
* Once it has an (app name, domain name) pair it compares this against the white and black lists to decide whether to block it or not.  
* If it is to be blocked then the firewall sends TCP RST packets to the connection to force it to close.   

The firewall needs root permissions to sniff packets and send TCP RST packets  so it installs a privileged helper to carry out these actions (you're asked to give a password to allow this helper to be installed when the firewall is first started).

One nice thing about this approach is that the firewall does not lie in the direct path of network packets i.e. network packets do not have to flow via the firewall.  That means if the firewall is stopped abruptly or is misconfigured then no real damage is done, network connectivity will be maintained.  Another is that it keeps things lightweight and non-invasive -- to install /uninstall just copy/delete the firewall app from your Applications folder, there's nothing more to it.

The main downside of the approach is that a small number of packets can occasionally "leak" on a connection before it is shut down, especially when apps make multiple rapid connection attempts in a row (e.g. in response to being blocked).  This doesn't seem like too big a deal though since its "privacy" (severely throttling tracking etc) that we're aiming for rather than strict "security".   See [Known Issues](https://github.com/doug-leith/appFirewall/blob/master/KNOWN_ISSUES.md) for more information.

## Privacy

No personal data is shared by this app. 

If you refresh the hostname files (with lists of blacklisted domains) then the web site that hosts the file may log the request (and so your IP address etc).  Refresh of hostname files is manual only, i.e. only when you press the "Refresh Lists" button on the app preferences page, so you have complete control over this.  

If the app crashes (hopefully not !) then it will send a short backtrace to https://leith.ie to help with debugging.  There is no personal information in this backtrace, an example of one is the following:

    0   appFirewall                         0x000000010dc3ae1e appFirewall   73246<br>
    1   libsystem_platform.dylib            0x00007fff769b5b5d _sigtramp   29<br>
    2   ???                                 0x000000011d3f8b76 0x0   4785671030<br>
    3   libsystem_c.dylib                   0x00007fff76822d8a raise   26<br>
    4   appFirewall                         0x000000010dc4fab5 appFirewall   158389<br>
    5   appFirewall                         0x000000010dc5001b appFirewall   159771<br>

Its a list of entry points in the app so that I can see where it crashed, nothing more.  There is no identifer linking this backtrace to the partricular instance of the app that you are running and the upload server does not log IP address or other connection details.

The app settings can be configured to check github monthly for updates, and automatically downloads and installs them, but this is disabled by default.   Github logs traffic to the repository and displays counts of downloads etc which are publicly visible (feel free to check them [here](https://github.com/doug-leith/appFirewall/graphs/traffic), Github's privacy policy is [here](https://help.github.com/en/github/site-policy/github-privacy-statement#what-information-github-collects) ).

## App store

The firewall isn't on the app store because the sandbox that app store apps must use blocks access to the [proc_listpids() and proc_pidfdinfo()](https://opensource.apple.com/source/xnu/xnu-3248.60.10/bsd/kern/proc_info.c.auto.html) syscalls used to monitor running processes.   

## Uninstall

The firewall consists of two parts, the main appFirewall app with the UI etc and a privileged helper app that does the connection blocking.  To fully uninstall delete the appFirewall app and the files  /Library/PrivilegedHelperTools/com.leith.appFirewall-Helper and /Library/LaunchDaemons/com.leith.appFirewall-Helper.plist

## Source code

See [github](https://github.com/doug-leith/appFirewall/)

## Contributing

New ideas and help with development always welcome !   The way to do propose code changes is to fork your own branch from the repository here, then send me an email with proposed changes and a link to the branch.   To report bugs or make feature requests please use the github issue tracking system (see tabs at top of this page).

## Authors

[Doug Leith](https://www.scss.tcd.ie/doug.leith)

## License

[BSD 3 License](https://opensource.org/licenses/BSD-3-Clause)

