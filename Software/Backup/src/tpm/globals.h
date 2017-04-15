#ifndef GLOBALS_H
#define GLOBALS_H
#include "authHandler.h"


// TWI clock freq
#define SCLFREQ 100000

// USART bps
#define BAUD 57600UL

// input buffer size
#define INBUFSIZE	41	// account for terminator

// typedefs
//typedef enum { false, true } bool_t;

typedef struct tdAuthSession
{
	uint8_t	handle[4];
	uint8_t	nonceEven[20];
	uint8_t	nonceOdd[20];
	uint8_t	HMACKey[20];
} authSession_t;

// structure for doing HMAC calculations
typedef struct tdHMAC
{
	uint8_t	paramDigest[20];
	uint8_t	nonceEven[20];
	uint8_t	nonceOdd[20];
	uint8_t	contAuth;
}	HMAC_t;

// structure for passing OSAP parameters
typedef struct tdOSAPparms
{
	uint8_t	entityType[2];
	uint8_t	entityValue[4];
	uint8_t	entityAuth[20];
}	OSAPparms_t;

// generic command output struct
typedef struct tdTPM_return
{
	uint8_t	tag[2];
	uint8_t	paramSize[4];
	uint8_t	returnCode[4];
	uint8_t	payLoad;				// marker
} TPM_return;

// externs

// auth session cache stuff
extern authSession_t	authSessions[2];
extern uint8_t			currentAuthSession;
extern uint8_t			ordinal[SZ_ORD];

// OSAP session parameters
extern OSAPparms_t OSAPparms;

// general purpose work buffers for pubKeys, signatures, blobs, etc.
extern uint8_t	workBuf0[256], workBuf1[256], workBuf2[256], workBuf3[256];

// HMAC calc buffer
extern HMAC_t	HMACBuf;

// IO buffer
extern uint8_t xferBuf[1024];

// number of bytes to send / receive
extern uint16_t numBytes;


#endif
