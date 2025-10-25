### Bursts of short, fast connections can leak a few packets

Here's a harsh test for the firewall.   Open a command-line terminal using Command-T and create a rapid burst of connection attempts by typing the following at the command line:

    for i in {1..20}; do curl http://sb.scorecardresearch.com & done

You might see some connections succeed in getting a "Please visit www.scorecardresearch.com for more information about our program" response.  This is a tough test for the firewall since the connections are very short - just two outgoing packets ([SYN](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment) and then the HTTP request) and two response packets ([SYN-ACK](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment) and HTTP response) - and very fast (the connection attempts are all made concurrently due to the & at the end of the curl command).  So this gives an idea of worst case behaviour.

If we'd used HTTPS rather than HTTP then there is a crypto handshake at the start of the connection which is several packets long.  This gives the firewall enough time to close the connection before any data is exchanged.    For example, type the following at the command line:

    for i in {1..20}; do curl https://sb.scorecardresearch.com & done

and note the connection is now https, but the setup is otherwise the same as before.  You should see that all of the connections are now consistently blocked during the crypto handshake (an error message "OpenSSL SSL_connect: SSL_ERROR_SYSCALL" is shown).

### Multiple domains can share the same IP address

The firewall observes the IP address of each network connection, and then tries to figure out the domain name (e.g. www.google-analytics.com) corresponding to that IP address in order to decide whether to block the connection or not.  However, it is possible, indeed quite common, for one IP address to be shared by multiple domains. 

Often the domains are closely related, in which case things are fine.  For example, api.dropbox.com and api.dropboxapi.com are both associated with IP address 162.125.64.7.  SImilarly, ssl-google-analytics.l.google.com, www.googletagmanager.com, www-googletagmanager.l.google.com and  ssl.google-analytics.com are all associated with IP address 74.125.193.97.

Otherwise some care is needed.  Since the firewall can block connections on a per app basis, if different apps connect to different domains sharing the same IP address then we can still block/pass connections as usual since we can use the app to distinguish between the domains.  However, if the same app connects to domains sharing the same IP address and we'd like to block one domain but pass the other then that's not possible just now.  But this seems already a strange situation since domains sharing the same IP address (and so likely hosted on the same server or cluster of servers) can obviously easily share information and so it seems sensible to either block both or pass both.   So in practice sharing of IP addresses by domains doesn't seem like such a big deal.

You can see information on the domains sharing an IP address by hovering your mouse over a connection - the tool tip gives connection details, including domains.  The number in brackets after a domain name indicates the number of times that domain name was recently resolved to the IP address.  So we can see, for example, whether one domain name is much more frequent than others.

### Enabling DNS over HTTPS in Firefox/Chrome prevents resolution of IP addresses

When DNS over HTTPS is enabled internally within Firefox (and Chrome) they perform encrypted lookups from within the application itself and so they are hidden from the firewall, at least for the moment.   That means the firewall can't convert the IP addresses they use to more readable domain names e.g. 2a00:1450:400b:c01::71 to www.google-analytics.com.

A good workaround is to enable the embedded DNS-over-HTTPS server in the appFirewall preferences (this uses [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy)) and disable the internal use of DNS over HTTPS within Firefox/Chrome (in Firefox navigate to about:config and set "network.trr.mode" to 0, in Chrome navigate to chrome://flags/ and set "Secure DNS lookups" to Disabled).   This also has the advantage of encrypting DNS for all apps (not just browsers).

### Filtering of VPN traffic is unreliable/experimental

Traffic sent via a VPN tunnel interface is logged but blocking of connections is unreliable at the moment, at least when using openvpn (which is all that I've tested).  That means connections which are marked to be blocked may fail to be blocked and so show up in the "Active Connections" tab.   The problem lies in openvpn itself so other VPN clients might be fine.    Note: proxied traffic is neither logged nor filtered (yet).

### Google QUIC connections are not selectively blocked (yet)

The firewall blocks TCP connections.  Google Chrome often uses an alternative UDP-based protocol called QUIC to connect to google services (other services don't support it yet).  This protocol is currently being standardised, and in the future so other browsers/apps and other services may well start using QUIC too.  Extending the firewall to allow blocking of QUIC connections is another "to do" list item.  For now a workaround is to enable blocking of QUIC connections in the appFirewall preferences, which will force fall back to use of TCP (this is a safe, but not v elegant, solution).   

### Filtering of IPv6 connections can be slow

If an IPv6 connection is already ongoing when the firewall starts then it can sometimes take the firewall a while to force the connection to stop.   This is because of some frustrating historical decisions re implementing IPv6 raw sockets in MacOS (and also other BSD-based OS's), so unfortunately there's no easy workaround (Network Extensions in Catalina or other similar kernel extensions don't resolve this).
