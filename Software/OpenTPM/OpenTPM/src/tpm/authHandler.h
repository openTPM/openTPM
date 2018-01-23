#ifndef AUTHHANDLER_H
#define AUTHHANDLER_H

#include <asf.h>
// #defines

#define SZ_ORD				4
#define ORD_OFFSET			6

#define SZ_RETCODE			4
#define RETCODE_OFFSET		6

#define SZ_DIGEST			20
#define SZ_AUTHVAL			20

#define SZ_INAUTH 			45
#define AUTH1_SIZE  		SZ_INAUTH
#define AUTH2_SIZE 			(AUTH1_SIZE + AUTH1_SIZE)

#define SZ_HAND				4
#define HAND1_SIZE  		SZ_HAND
#define HAND2_SIZE  		(HAND1_SIZE + HAND1_SIZE)

#define PAYLOAD_START_OFF	10
#define SZ_OUTAUTH			41
#define SZ_CONT				1


// typedefs
typedef struct tdOutAuth
{
	uint8_t	nonceEven[20];
	uint8_t	contAuth;
	uint8_t	HMACout[20];
}	outAuth;

// prototypes
uint8_t inAuthHandler(uint8_t numAuths, uint8_t numInHandles);
uint8_t outAuthHandler(uint8_t numAuths, uint8_t numOutHandles);
void encAuthHandler(uint8_t *pNonceBuf, uint8_t *pHMACkey, uint8_t *outPtr);
void dumpHMACparms(uint8_t numAuthSession, uint8_t *HMACoutBuf);

#endif
