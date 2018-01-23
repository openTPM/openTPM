// central place to define all the global working buffers

#include <stdio.h>
#include <string.h>
//#include <asf.h>

#include "globals.h"
#include "authHandler.h"

// auth session cache
authSession_t	authSessions[2];
uint8_t	currentAuthSession;
uint8_t ordinal[SZ_ORD];

// general purpose work buffers for pubKeys, signatures, blobs, etc.
uint8_t	workBuf0[256], workBuf1[256], workBuf2[256];
uint8_t	workBuf3[256];

// HMAC calc buffer
HMAC_t	HMACBuf;

// OSAP session parameters
OSAPparms_t OSAPparms;

// IO buffer
uint8_t xferBuf[1024];

// number of bytes to send / receive
uint16_t numBytes;
