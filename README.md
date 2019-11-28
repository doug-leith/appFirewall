# AppFirewall

A free, fully open-source application firewall for MAC OS Mojave and later.  Allows real-time monitoring of network connections being made by applications, and blocking/allowing of these per app by user.  Supports use of hostname lists (Energized Blu etc) to block known tracker and advertising domains for all apps.  Also allows blocking of all network connections for specified apps, blocking of all connections except for specified whitelisted connections, use of pre-configured lists of connections per app to allow/block etc.  

## Getting Started

Just drag the appFirewall icon into your Applications folder and click on it to start, there's nothing more to it.

## Privacy - What data we collect

The short answer is "none".  No personal data is shared by this app. 

If you refresh the hostname files (with lists of blacklisted domains) then the web site that hosts the file may log the request (and so your IP address etc).  Refresh of hostname files is manual only, i.e. only when you press the "Refresh Lists" button on the app preferences page, so you have complete control over this.

If the app crashes (hopefully not !) then it will send a short backtrace to http://leith.ie to help with debugging.  There is no personal information in this backtrace, an example is the following:

    0   appFirewall                         0x000000010dc3ae1e appFirewall   73246<br>
    1   libsystem_platform.dylib            0x00007fff769b5b5d _sigtramp   29<br>
    2   ???                                 0x000000011d3f8b76 0x0   4785671030<br>
    3   libsystem_c.dylib                   0x00007fff76822d8a raise   26<br>
    4   appFirewall                         0x000000010dc4fab5 appFirewall   158389<br>
    5   appFirewall                         0x000000010dc5001b appFirewall   159771<br>

(its a list of entry points in the app so that I can see where it crashed, nothing more).  The http://leith.ie web server does not log IP address or other connection details.

## Contributing

New ideas and help with development always welcome !   The way to do it is to fork your own branch from the repository here, then send me an email with proposed changes and a link to the branch.

## Authors

[Doug Leith](https://www.scss.tcd.ie/doug.leith)

## License

[BSD 3 License](https://opensource.org/licenses/BSD-3-Clause)

