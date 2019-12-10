### Bursts of short, fast connections can leak a few packets

Here's a harsh test for the firewall.   Open a command-line terminal using Command-T and create a rapid burst of connection attempts by typing the following at the command line:

    for i in {1..20}; do curl http://sb.scorecardresearch.com & done

You should see many connections get a "Please visit www.scorecardresearch.com for more information about our program" response.  This is a tough test for the firewall since the connections are very short - just two outgoing packets (SYN and then the HTTP request) and two response packets (SYN-ACK and HTTP response) - and very fast (the connection attempts are all made concurrently due to the & at the end of the curl command).  So this gives an idea of worst case behaviour.

If we'd used HTTPS rather than HTTP then there is a crypto handshake at the start of the connection which is several packets long.  This gives the firewall enough time to close the connection before any data is exchanged.    For example, type the following at the command line:

    for i in {1..20}; do curl https://sb.scorecardresearch.com & done

and note the connection is now https, but the setup is otherwise the same as before.  You should see that all of the connections are now blocked during the crypto handshake (an error message "OpenSSL SSL_connect: SSL_ERROR_SYSCALL" is shown).

### Multiple domains can share the same IP address

The firewall observes the IP address of each network connection, and then tries to figure out the domain name (e.g. www.google-analytics.com) corresponding to that IP address in order to decide whether to block the connection or not.  However, it is possible for one IP address to be shared by multiple domains. 

Often the domains are closely related, in which case things are fine.  For example, api.dropbox.com and api.dropboxapi.com are both associated with IP address 162.125.64.7.

Otherwise some care is needed.  Since the firewall can block connections on a per app basis, if different apps connect to different domains sharing the same IP address then we can still block/pass connections as usual since we can use the app to distinguish between the domains.  However, if the same app connects to domains sharing the same IP address and we'd like to block one domain but pass the other then that's not possible just now.  But this seems already a strange situation since domains sharing the same IP address can obviously easily share information and so it seems sensible to either block both or pass both.

You can see information on the domains sharing an IP address by hovering your mouse over a connection - the tool tip gives connection details, including domains.  The number in brackets after a domain name indicates the number of times that domain name was recently resolved to the IP address.  So we can see, for example, whether one domain name is much more frequent than others.
