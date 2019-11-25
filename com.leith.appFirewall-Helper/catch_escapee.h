//
//  catch_escapee.h
//  appFirewall
//


#ifndef catch_escapee_h
#define catch_escapee_h

#include <stdio.h>
#include <unistd.h>
#include <libproc.h>
#include <fcntl.h>
#include "pcap_sniffer.h"
#include "send_rst.h"

#define CATCHER_PORT 5

void start_catcher_listener(void);

#endif /* catch_escapee_h */
