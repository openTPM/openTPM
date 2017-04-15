#ifndef NVSTOREFUNCS_H
#define NVSTOREFUNCS_H

#include "globals.h"
#include <asf.h>
// #defines

// identifiers for cached items
#define KEY_INVALID 0x00
#define KEY_VALID	0x01 	// key
#define BLOB_VALID	0x02	// sealed blob
#define SIGN_VALID	0x03	// signature

// handleSlot is invalid
#define INVALID_HANDLE	0xFF

// typedefs

// these build up the fixed part of a TPM_Key structure
typedef struct _RSA_keyParms
{
	uint8_t			keyLength[4];
	uint8_t			numPrimes[4];
	uint8_t			exponentSize[4]; 	// always 0 since TPM uses default exponent
} RSA_keyParms;

typedef struct _algParms
{
	uint8_t			algoritmID[4];
	uint8_t			encScheme[2];
	uint8_t			sigScheme[2];
	uint8_t			parmSize[4];
	RSA_keyParms	RSAParms;
} algParms;

typedef struct __tagFill
{
	uint8_t			tag[2];
	uint8_t			fill[2];
} _tagFill;

typedef union _tagVer
{
	_tagFill 		tagFill;
	uint8_t 		version[4];
} tagVer;

typedef struct _keyFixed
{
	tagVer			tagVersion; 		// tag/fill for key12, version for key11
	uint8_t			keyUsage[2];
	uint8_t			keyFlags[4];
	uint8_t			authDataUsage;
	algParms		keyParms;
	uint8_t			PCRinfoSize[4];
}	keyFixed;

// define structure for the local key cache
typedef struct _keyStoreStruct
{
	uint8_t		keyValid; 				// valid: this slot holds a TPM_KEY struct
	uint16_t	keySize;
	uint8_t		keyAuth[20];
	uint8_t		keyData[613];
}	keyStoreStruct;

// define structure for key loaded in TPM
typedef struct _loadedKeyStruct
{
	uint8_t		keyValid;				// valid: currently loaded in TPM
	uint8_t		keyAuth[20];
	uint8_t		keyHandle[4];
}	loadedKeyStruct;

typedef struct __tagET
{
	uint8_t			tag[2];
	uint8_t			ET[2];
} _tagET;

typedef union _tagETVer
{
	_tagET	 		tagET;
	uint8_t 		version[4];
} tagETVer;

// split struct to handle variable length member
typedef struct _storedData_a
{
	tagETVer		tagET_Version; 		// tag/et for stored_data12, version for stored_data
	uint8_t			SealInfoSize[4];
	uint8_t			SealInfo;			// marker, is SealInfoSize bytes
}	storedData_a;

typedef struct _storedData_b
{
	uint8_t			EncDataSize[4];
	uint8_t			EncData;			// marker, is EncDataSize bytes
}	storedData_b;

typedef struct _storedDataFixed
{
	tagETVer		tagET_Version; 		// tag/et for stored_data12, version for stored_data
	uint8_t			SealInfoSize[4];
}	storedDataFixed;

typedef struct _signedData
{
	uint8_t			sigSize[4];
	uint8_t			sig;
}	signedData;

typedef struct _store_Pubkey
{
	uint8_t			keySize[4];
	uint8_t			pubKeyDat;				// marker, is keySize bytes
}	store_Pubkey;

typedef struct _TPM_Pubkey
{
	algParms			algorithmParms;
	store_Pubkey		ST_pubKey;
}	TPM_Pubkey;


// protos

// initializations
void initLoadedKeyStore(void);
void initKeyStore(void);

// cache funcs for keys
void saveKeyToEE(uint8_t keySlot, uint8_t *pKeyAuth);
uint16_t getKeyFromEE(uint8_t keySlot, uint8_t *outBuf);
bool keySlotValid(uint8_t keySlot);

// cache funcs for blobs (seal in/out)
bool blobSlotValid(uint8_t keySlot);
void saveBlobToEE(uint8_t keySlot);
uint16_t getBlobFromEE(uint8_t keySlot, uint8_t *outBuf);

// cache funcs for signatures
void saveSigToEE(uint8_t keySlot);
uint16_t getSigFromEE(uint8_t keySlot, uint8_t *outBuf);
bool sigSlotValid(uint8_t keySlot);

// minimalistic API for TPM key management (tracks loaded keyHandles)
uint8_t saveKeyHandle(uint8_t keySlot, uint8_t *pHandle);
bool getLoadedKeyHandle(uint8_t handleSlot, uint8_t *outBuf);
bool getLoadedKeyAuth(uint8_t handleSlot, uint8_t *outBuf);
bool handleSlotValid(uint8_t handleSlot);
uint8_t findKeyHandle(uint32_t handleNum);
bool flushKeyHandle(uint8_t handleSlot);
uint8_t getKnownKeyHandles(uint8_t *outBuf);

// owner / SRK storage / retrieval funcs
bool saveOwnerAuth(uint8_t *authBuf);
bool getOwnerAuth(uint8_t *authBuf);
bool saveSRKAuth(uint8_t *authBuf);
bool getSRKAuth(uint8_t *authBuf);

/*
uint8_t nvm_write(uint8_t *psrc, uint32_t *pdest, uint16_t size);
uint8_t nvm_write_byte(uint32_t *pdest, uint8_t value);
uint8_t nvm_write_word(uint32_t *pdest, uint16_t value);
uint8_t nvm_write_block(uint8_t *psrc, uint32_t *pdest, uint16_t size);



uint8_t nvm_read(uint8_t *pdest, uint32_t *psrc, uint16_t size);
uint8_t nvm_read_byte(uint32_t *psrc);
uint16_t nvm_read_word(uint32_t *psrc);
uint8_t nvm_read_block(uint8_t *pdest, uint32_t *psrc, uint16_t size);

uint8_t nvm_setup(uint8_t *psrc, uint32_t *pdest, uint16_t size);
void nvm_unit_test(void);
*/

#endif


