//
//  netstats.h
//  appFirewall
//
//  Created by Doug Leith on 04/01/2020.
//
// 	Based on: Jonathan Levin, http://NewOSXBook.com/
//  http://newosxbook.com/src.jl?tree=listings&file=netbottom.c

#ifndef netstats_h
#define netstats_h

#include <stdio.h>
#include <dispatch/dispatch.h>
#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "util.h"
#include "connection.h"
#include "circular_list.h"

// The missing NetworkStatistics.h...
typedef void 	*NStatManagerRef;
typedef void 	*NStatSourceRef;

NStatManagerRef	NStatManagerCreate (const struct __CFAllocator *,
			     dispatch_queue_t,
			     void (^)(void *, void *));

int NStatManagerSetInterfaceTraceFD(NStatManagerRef, int fd);
int NStatManagerSetFlags(NStatManagerRef, int Flags);
int NStatManagerAddAllTCPWithFilter(NStatManagerRef, int something, int somethingElse);
int NStatManagerAddAllUDPWithFilter(NStatManagerRef, int something, int somethingElse);
void *NStatSourceQueryDescription(NStatSourceRef);

extern CFStringRef kNStatProviderInterface;
extern CFStringRef kNStatProviderRoute;
extern CFStringRef kNStatProviderSysinfo;
extern CFStringRef kNStatProviderTCP;
extern CFStringRef kNStatProviderUDP;
extern CFStringRef kNStatSrcKeyAvgRTT;
extern CFStringRef kNStatSrcKeyChannelArchitecture;
extern CFStringRef kNStatSrcKeyConnProbeFailed;
extern CFStringRef kNStatSrcKeyConnectAttempt;
extern CFStringRef kNStatSrcKeyConnectSuccess;
extern CFStringRef kNStatSrcKeyDurationAbsoluteTime;
extern CFStringRef kNStatSrcKeyEPID;
extern CFStringRef kNStatSrcKeyEUPID;
extern CFStringRef kNStatSrcKeyEUUID;
extern CFStringRef kNStatSrcKeyInterface;
extern CFStringRef kNStatSrcKeyInterfaceCellConfigBackoffTime;
extern CFStringRef kNStatSrcKeyInterfaceCellConfigInactivityTime;
extern CFStringRef kNStatSrcKeyInterfaceCellUlAvgQueueSize;
extern CFStringRef kNStatSrcKeyInterfaceCellUlMaxQueueSize;
extern CFStringRef kNStatSrcKeyInterfaceCellUlMinQueueSize;
extern CFStringRef kNStatSrcKeyInterfaceDescription;
extern CFStringRef kNStatSrcKeyInterfaceDlCurrentBandwidth;
extern CFStringRef kNStatSrcKeyInterfaceDlMaxBandwidth;
extern CFStringRef kNStatSrcKeyInterfaceIsAWD;
extern CFStringRef kNStatSrcKeyInterfaceIsAWDL;
extern CFStringRef kNStatSrcKeyInterfaceIsCellFallback;
extern CFStringRef kNStatSrcKeyInterfaceIsExpensive;
extern CFStringRef kNStatSrcKeyInterfaceLinkQualityMetric;
extern CFStringRef kNStatSrcKeyInterfaceName;
extern CFStringRef kNStatSrcKeyInterfaceThreshold;
extern CFStringRef kNStatSrcKeyInterfaceType;
extern CFStringRef kNStatSrcKeyInterfaceTypeCellular;
extern CFStringRef kNStatSrcKeyInterfaceTypeLoopback;
extern CFStringRef kNStatSrcKeyInterfaceTypeUnknown;
extern CFStringRef kNStatSrcKeyInterfaceTypeWiFi;
extern CFStringRef kNStatSrcKeyInterfaceTypeWired;
extern CFStringRef kNStatSrcKeyInterfaceUlBytesLost;
extern CFStringRef kNStatSrcKeyInterfaceUlCurrentBandwidth;
extern CFStringRef kNStatSrcKeyInterfaceUlEffectiveLatency;
extern CFStringRef kNStatSrcKeyInterfaceUlMaxBandwidth;
extern CFStringRef kNStatSrcKeyInterfaceUlMaxLatency;
extern CFStringRef kNStatSrcKeyInterfaceUlMinLatency;
extern CFStringRef kNStatSrcKeyInterfaceUlReTxtLevel;
extern CFStringRef kNStatSrcKeyInterfaceWifiConfigFrequency;
extern CFStringRef kNStatSrcKeyInterfaceWifiConfigMulticastRate;
extern CFStringRef kNStatSrcKeyInterfaceWifiDlEffectiveLatency;
extern CFStringRef kNStatSrcKeyInterfaceWifiDlErrorRate;
extern CFStringRef kNStatSrcKeyInterfaceWifiDlMaxLatency;
extern CFStringRef kNStatSrcKeyInterfaceWifiDlMinLatency;
extern CFStringRef kNStatSrcKeyInterfaceWifiScanCount;
extern CFStringRef kNStatSrcKeyInterfaceWifiScanDuration;
extern CFStringRef kNStatSrcKeyInterfaceWifiUlErrorRate;
extern CFStringRef kNStatSrcKeyLocal;
extern CFStringRef kNStatSrcKeyMinRTT;
extern CFStringRef kNStatSrcKeyPID;
extern CFStringRef kNStatSrcKeyProbeActivated;
extern CFStringRef kNStatSrcKeyProcessName;
extern CFStringRef kNStatSrcKeyProvider;
extern CFStringRef kNStatSrcKeyRcvBufSize;
extern CFStringRef kNStatSrcKeyRcvBufUsed;
extern CFStringRef kNStatSrcKeyReadProbeFailed;
extern CFStringRef kNStatSrcKeyRemote;
extern CFStringRef kNStatSrcKeyRouteDestination;
extern CFStringRef kNStatSrcKeyRouteFlags;
extern CFStringRef kNStatSrcKeyRouteGateway;
extern CFStringRef kNStatSrcKeyRouteGatewayID;
extern CFStringRef kNStatSrcKeyRouteID;
extern CFStringRef kNStatSrcKeyRouteMask;
extern CFStringRef kNStatSrcKeyRouteParentID;
extern CFStringRef kNStatSrcKeyRxBytes;
extern CFStringRef kNStatSrcKeyRxCellularBytes;
extern CFStringRef kNStatSrcKeyRxDupeBytes;
extern CFStringRef kNStatSrcKeyRxOOOBytes;
extern CFStringRef kNStatSrcKeyRxPackets;
extern CFStringRef kNStatSrcKeyRxWiFiBytes;
extern CFStringRef kNStatSrcKeyRxWiredBytes;
extern CFStringRef kNStatSrcKeySndBufSize;
extern CFStringRef kNStatSrcKeySndBufUsed;
extern CFStringRef kNStatSrcKeyStartAbsoluteTime;
extern CFStringRef kNStatSrcKeyTCPCCAlgorithm;
extern CFStringRef kNStatSrcKeyTCPState;
extern CFStringRef kNStatSrcKeyTCPTxCongWindow;
extern CFStringRef kNStatSrcKeyTCPTxUnacked;
extern CFStringRef kNStatSrcKeyTCPTxWindow;
extern CFStringRef kNStatSrcKeyTrafficClass;
extern CFStringRef kNStatSrcKeyTrafficMgtFlags;
extern CFStringRef kNStatSrcKeyTxBytes;
extern CFStringRef kNStatSrcKeyTxCellularBytes;
extern CFStringRef kNStatSrcKeyTxPackets;
extern CFStringRef kNStatSrcKeyTxReTx;
extern CFStringRef kNStatSrcKeyTxWiFiBytes;
extern CFStringRef kNStatSrcKeyTxWiredBytes;
extern CFStringRef kNStatSrcKeyUPID;
extern CFStringRef kNStatSrcKeyUUID;
extern CFStringRef kNStatSrcKeyVUUID;
extern CFStringRef kNStatSrcKeyVarRTT;
extern CFStringRef kNStatSrcKeyWriteProbeFailed;
extern CFStringRef kNStatSrcTCPStateCloseWait;
extern CFStringRef kNStatSrcTCPStateClosed;
extern CFStringRef kNStatSrcTCPStateClosing;
extern CFStringRef kNStatSrcTCPStateEstablished;
extern CFStringRef kNStatSrcTCPStateFinWait1;
extern CFStringRef kNStatSrcTCPStateFinWait2;
extern CFStringRef kNStatSrcTCPStateLastAck;
extern CFStringRef kNStatSrcTCPStateListen;
extern CFStringRef kNStatSrcTCPStateSynReceived;
extern CFStringRef kNStatSrcTCPStateSynSent;
extern CFStringRef kNStatSrcTCPStateTimeWait;

CFStringRef NStatSourceCopyProperty (NStatSourceRef , CFStringRef);
void NStatSourceSetDescriptionBlock (NStatSourceRef arg,  void (^)(CFDictionaryRef));
void NStatSourceSetRemovedBlock (NStatSourceRef arg,  void (^)(void));

int lookup_nstat(conn_raw_t *cr, char* name, int* pid);
void start_netstats(void);

#endif /* netstats_h */
