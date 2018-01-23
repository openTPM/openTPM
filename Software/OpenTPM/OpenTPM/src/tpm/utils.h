#ifndef UTILS_H
#define UTILS_H
#include <asf.h>

#include "commandStructs.h"
//defines
#define BS_CHAR 0x08

// typedefs
typedef enum { fixedRandom, realRandom } randType;
typedef enum { fixedNonce, realNonce } nonceType;
typedef enum { includeSRK, excludeSRK } SRKopt;

// overlay defs for easier dealing with TPM I/O
typedef struct tdOSAPIn
{
	uint8_t	tag[2];
	uint8_t	parmamSize[4];
	uint8_t	ordinal[4];
	uint8_t	entityType[2];
	uint8_t	entityValue[4];
	uint8_t	nonceOddOSAP[20];
}	OSAPIn;

typedef struct tdOSAPOut
{
	uint8_t	tag[2];
	uint8_t	parmamSize[4];
	uint8_t	returnCode[4];
	uint8_t	authHandle[4];
	uint8_t	nonceEven[20];
	uint8_t	nonceEvenOSAP[20];
}	OSAPOut;

typedef struct tdOSAPHashBuf
{
	uint8_t	nonceEvenOSAP[20];
	uint8_t	nonceOddOSAP[20];
}	OSAPHashBuf;


// protos

void convertLongToArray(uint32_t inVal, uint8_t *addr);
void convertIntToArray(uint16_t inVal, uint8_t *addr);
uint16_t convertArrayToInt( uint8_t *addr );
uint32_t convertArrayToLong( uint8_t *addr );
void getRandomNum(uint8_t *dest, uint16_t count, randType randFlag);
void getNonceOdd(uint8_t *dest, nonceType nonceFlag);
//void OSAPHandler( void *pCommand );
void OSAPHandler( TPM_Command *pCommand );
//uint8_t	selectHandleSlot(uint8_t *workBuf, SRKopt SRKflag);
uint8_t	selectHandleSlot(uint8_t *workBuf, char* promptSTr, SRKopt SRKflag);
void showKnownKeys(void );
void flushBS(char *bufp);

void resetTPM(void);

// wrappers for printf protos that automatically flush (for CDC USB)
extern int printf_flush(char *fmt, ...);
extern int printf_P_flush(char* fmt, ...);
void send_usb(uint16_t tx_length, char *tx_buffer);

//void printf(char *fmt , ...);
#endif
