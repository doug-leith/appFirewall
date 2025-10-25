/*
 *  libnet
 *  libnet.h - Network routine library header file
 *  include/libnet.h.  Generated from libnet.h.in by configure.
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __LIBNET_H
#define __LIBNET_H

/**
 * @file libnet.h
 * @brief Top-level libnet header file
 * 
 * @details This section doesn't contain any details about libnet.h.
 *
 * For details, see libnet-functions.h and libnet-macros.h
 */

#ifdef __cplusplus
extern "C" {
#endif

 /*
 * TODO move the stuff we ALWAYS need out of the DOXYGEN ifndef block
 * and minimize their redundancies (see doc/TODO)
 */
#ifndef DOXYGEN_SHOULD_SKIP_THIS
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

#include <errno.h>
#include <stdarg.h>

#if !defined(_MSC_VER)
#include <unistd.h>
#endif

#if defined(HAVE_SYS_SOCKIO_H) && !defined(SIOCGIFADDR)
#include <sys/sockio.h>
#endif

#if !defined(__WIN32__)
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#else /* __WIN32__ */
#if (__CYGWIN__)
#include <sys/socket.h>
#endif
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#endif /* __WIN32__ */

#if (HAVE_NET_ETHERNET_H)
#include <net/ethernet.h>
#endif  /* HAVE_NET_ETHERNET_H */

#define LIBNET_VERSION  "1.3"

#define LIBNET_LIL_ENDIAN 1

#ifndef LIBNET_API
#define LIBNET_API
#endif
#endif /* DOXYGEN_SHOULD_SKIP_THIS */

#include "./libnet/libnet-types.h"
#include "./libnet/libnet-macros.h"
#include "./libnet/libnet-headers.h"
#include "./libnet/libnet-structures.h"
#include "./libnet/libnet-asn1.h"
#include "./libnet/libnet-functions.h"

#ifdef __cplusplus
}
#endif

#endif  /* __LIBNET_H */

