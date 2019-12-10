### Bursts of short, fast connections can leak a few packets

Here's a harsh test for the firewall.   Open a command-line terminal using Command-T and create a rapid burst of connection attempts by typing the following at the command line:

    for i in {1..20}; do curl http://sb.scorecardresearch.com & done

You should see many connections get a "Please visit www.scorecardresearch.com for more information about our program" response.  This is a tough test for the firewall since the connections are very short - just two outgoing packets (SYN and then the HTTP request) and two response packets (SYN-ACK and HTTP response) - and very fast (the connection attempts are all made concurrently due to the & at the end of the curl command).  So this gives an idea of worst case behaviour.

If we'd used HTTPS rather than HTTP then there is a crypto handshake at the start of the connection which is several packets long.  This gives the firewall enough time to close the connection before any data is exchanged.    For example, type the following at the command line:

    for i in {1..20}; do curl https://sb.scorecardresearch.com & done

and note the connection is now https, but the setup is otherwise the same as before.  You should see that all of the connections are now blocked during the crypto handshake (an error message "OpenSSL SSL_connect: SSL_ERROR_SYSCALL" is shown).

### Multiple domains can share the same IP address
