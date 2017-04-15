#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "commandStructs.h"
#include "nvStoreFuncs.h"
#include "commandFuncs.h"
#include "authHandler.h"
#include "authHandler.h"
#include "physical.h"
#include "globals.h"
#include "utils.h"
#include "conf_board.h"


#define NVM_READ_FULL_BUFFER_WORD_SIZE 16*(IFLASH_PAGE_SIZE / sizeof(uint32_t))
#define NVM_READ_HALF_BUFFER_WORD_SIZE 8*(IFLASH_PAGE_SIZE / sizeof(uint32_t))

#define NVM_READ_FULL_BUFFER_BYTE_SIZE 4*NVM_READ_FULL_BUFFER_WORD_SIZE
#define NVM_READ_HALF_BUFFER_BYTE_SIZE 4*NVM_READ_HALF_BUFFER_WORD_SIZE

// EEPROM storage allocations
static keyStoreStruct	keyStore[5]; 		// internal key cache
static loadedKeyStruct	loadedKeyStore[20]; // TPM loaded key handles

/* owner and SRK auth storage */
static uint8_t	ownerAuthEE[20];
static uint8_t	SRKAuthEE[20];

typedef unsigned long UL;


struct {

	uint32_t* ownerAuthEE;		/* FLASH page address */
	uint32_t* SRKAuthEE;		/* FLASH page address */
	} nvmAddr_var_t = {

	(uint32_t*)0x005FEC40,
	(uint32_t*)0x005FEC54,

};

/* KeyStore */
struct {

	uint32_t* keyValid[5];		/* FLASH page address, holds uint8_t */
	uint32_t* keySize[5];		/* FLASH page address, holds uint16_t */
	uint32_t* keyAuth[5];		/* FLASH page address, holds uint8_t [20] */
	uint32_t* keyData[5];		/* FLASH page address, holds uint8_t [613]*/

	} nvmAddr_KeyStore_t = {
	/* KeyValid FLASH Memory Address */
	{(uint32_t*)0x005FE000, (uint32_t*)0x005FE004, (uint32_t*)0x005FE008, (uint32_t*)0x005FE00C, (uint32_t*)0x005FE010},
	/* KeySize FLASH Memory Address */
	{(uint32_t*)0x005FE014, (uint32_t*)0x005FE018, (uint32_t*)0x005FE01C, (uint32_t*)0x005FE020, (uint32_t*)0x005FE024},
	/* KeyAuth FLASH Memory Address */
	{(uint32_t*)0x005FE028, (uint32_t*)0x005FE03C, (uint32_t*)0x005FE050, (uint32_t*)0x005FE064, (uint32_t*)0x005FE078},
	/* KeyData FLASH Memory Address */
	{(uint32_t*)0x005FE07C, (uint32_t*)0x005FE2E4, (uint32_t*)0x005FE54C, (uint32_t*)0x005FE7B4, (uint32_t*)0x005FEA1C},
};


/* LoadedKey */
struct {

	uint32_t* keyValid[20];			/* FLASH page address, holds uint8_t */
	uint32_t* keyAuth[20];		    /* FLASH page address, holds uint8_t [20] */
	uint32_t* keyHandle[20];		/* FLASH page address, holds uint8_t [4] */
	
	} nvmAddr_loadedKeyStore_t = {
	/* KeyValid FLASH Memory Address */
	{	(uint32_t*)0x005FEA20, (uint32_t*)0x005FEA24, (uint32_t*)0x005FEA28, (uint32_t*)0x005FEA2C, (uint32_t*)0x005FEA30,
		(uint32_t*)0x005FEA34, (uint32_t*)0x005FEA38, (uint32_t*)0x005FEA3C, (uint32_t*)0x005FEA40, (uint32_t*)0x005FEA44,
		(uint32_t*)0x005FEA48, (uint32_t*)0x005FEA4C, (uint32_t*)0x005FEA50, (uint32_t*)0x005FEA54, (uint32_t*)0x005FEA58,
		(uint32_t*)0x005FEA5C, (uint32_t*)0x005FEA60, (uint32_t*)0x005FEA64, (uint32_t*)0x005FEA68, (uint32_t*)0x005FEA6C},
	/* KeyAuth FLASH Memory Address */
	{	(uint32_t*)0x005FEA70, (uint32_t*)0x005FEA84, (uint32_t*)0x005FEA98, (uint32_t*)0x005FEAAC, (uint32_t*)0x005FEAC0,
		(uint32_t*)0x005FEAD4, (uint32_t*)0x005FEAE8, (uint32_t*)0x005FEAFC, (uint32_t*)0x005FEB10, (uint32_t*)0x005FEB24,
		(uint32_t*)0x005FEB38, (uint32_t*)0x005FEB4C, (uint32_t*)0x005FEB60, (uint32_t*)0x005FEB74, (uint32_t*)0x005FEB88,
		(uint32_t*)0x005FEB9C, (uint32_t*)0x005FEBB0, (uint32_t*)0x005FEBC4, (uint32_t*)0x005FEBD8, (uint32_t*)0x005FEBEC},
	/* KeyHandle FLASH Memory Address */
	{	(uint32_t*)0x005FEBF0, (uint32_t*)0x005FEBF4, (uint32_t*)0x005FEBF8, (uint32_t*)0x005FEBFC, (uint32_t*)0x005FEC00,
		(uint32_t*)0x005FEC04, (uint32_t*)0x005FEC08, (uint32_t*)0x005FEC0C, (uint32_t*)0x005FEC10, (uint32_t*)0x005FEC14,
		(uint32_t*)0x005FEC18, (uint32_t*)0x005FEC1C, (uint32_t*)0x005FEC20, (uint32_t*)0x005FEC24, (uint32_t*)0x005FEC28,
		(uint32_t*)0x005FEC2C, (uint32_t*)0x005FEC30, (uint32_t*)0x005FEC34, (uint32_t*)0x005FEC38, (uint32_t*)0x005FEC3C},

};


/*
PAGE	ADDRESS   OFFSET
----------------------


2032	0x5FE000	0
2033	0x5FE200	0

2034	0x5FE400	0
2035	0x5FE600	0

2036	0x5FE800	0
2037	0x5FEA00	0

2038	0x5FEC00	0
2039	0x5FEE00	0

2040	0x5FF000	0
2041	0x5FF200	0

2042	0x5FF400	0
2043	0x5FF600	0

2044	0x5FF800	0
2045	0x5FFA00	0

2046	0x5FFC00	0
2047	0x5FFE00	0	  UNLOCK Sector(2032 - 2047) 8k

*/


/*****************************************************************************/
void saveBlobToEE(uint8_t keySlot)
{
	uint16_t	blobSize;
	uint8_t		*pPayload = &((TPM_return*) xferBuf)->payLoad;

	// parse the size of the TPM_STORED_DATA structure,
	// easiest to "walk" a pointer to get the size
	uint8_t *pStoredData = pPayload;
	pStoredData += sizeof(storedDataFixed);						// fixed/known part of struct
	pStoredData += convertArrayToLong(pStoredData-4);			// get/add sealInfoSize
	pStoredData += (4 + convertArrayToLong(pStoredData));		// encData

	blobSize = pStoredData - pPayload;							// returns size in bytes

	printf("\r\nblobSize is %d", blobSize);
	printf("\r\nwriting blob to NVM slot %d...", (keySlot+1));

// 	eeprom_write_block(pPayload, &keyStore[keySlot].keyData, blobSize);
// 	eeprom_write_word(&keyStore[keySlot].keySize, blobSize);
// 	eeprom_write_byte(&keyStore[keySlot].keyValid, BLOB_VALID);
	
	nvm_write_block(pPayload, nvmAddr_KeyStore_t.keyData[keySlot], blobSize); 
	nvm_write_word(nvmAddr_KeyStore_t.keySize[keySlot],blobSize);		
	nvm_write_byte(nvmAddr_KeyStore_t.keyValid[keySlot], BLOB_VALID);	

	printf("\r\nwriting done!");

}
/*****************************************************************************/
uint16_t getBlobFromEE(uint8_t keySlot, uint8_t *outBuf)
{
	uint16_t blobSize;

// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == BLOB_VALID)
// 	{
// 		blobSize = eeprom_read_word(&keyStore[keySlot].keySize);
// 		eeprom_read_block(outBuf, &keyStore[keySlot].keyData, blobSize);
// 	}
// 	else blobSize = 0;


	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == BLOB_VALID)
	{
		blobSize = nvm_read_word(nvmAddr_KeyStore_t.keySize[keySlot]);
		nvm_read_block(outBuf, nvmAddr_KeyStore_t.keyData[keySlot], blobSize);
	}
	else blobSize = 0;

	return blobSize;
}
/*****************************************************************************/
bool blobSlotValid(uint8_t keySlot)
{
	
// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == BLOB_VALID)
// 		return true;
// 	else
// 		return false;	
	
	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == BLOB_VALID)
		return true;
	else
		return false;
}
/*****************************************************************************/

void saveSigToEE(uint8_t keySlot)
{
    uint16_t	sigSize;

    // setup overlay
	signedData	*pSignedData = (signedData*) &((TPM_return*) xferBuf)->payLoad;

	// get signature size
	sigSize = (uint16_t) convertArrayToLong(pSignedData->sigSize);

	printf("\r\nsignatureSize is %d", sigSize);
	printf("\r\nwriting signature to EEPROM slot %d...", keySlot);

// 	eeprom_write_block(&pSignedData->sig, &keyStore[keySlot].keyData, sigSize);
// 	eeprom_write_word(&keyStore[keySlot].keySize, sigSize);
// 	eeprom_write_byte(&keyStore[keySlot].keyValid, SIGN_VALID);

	nvm_write_block(&pSignedData->sig, nvmAddr_KeyStore_t.keyData[keySlot], sigSize);
	nvm_write_word(nvmAddr_KeyStore_t.keySize[keySlot], sigSize);
	nvm_write_byte(nvmAddr_KeyStore_t.keyValid[keySlot], SIGN_VALID);

	printf("\r\nwriting done!");
}
/*****************************************************************************/
uint16_t getSigFromEE(uint8_t keySlot, uint8_t *outBuf)
{
	uint16_t signSize;

// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == SIGN_VALID)
// 	{
// 		signSize = eeprom_read_word(&keyStore[keySlot].keySize);
// 		eeprom_read_block(outBuf, &keyStore[keySlot].keyData, signSize);
// 	}
// 	else signSize = 0;
	
	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == SIGN_VALID)
	{
		signSize = nvm_read_word(nvmAddr_KeyStore_t.keySize[keySlot]);
		nvm_read_block(outBuf, nvmAddr_KeyStore_t.keyData[keySlot], signSize);
	}
	else signSize = 0;	
	

	return signSize;
}
/*****************************************************************************/
bool sigSlotValid(uint8_t keySlot)
{
	
// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == SIGN_VALID)
// 	return true;
// 	else
// 	return false;
	
	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == SIGN_VALID)
	return true;
	else
	return false;	
}

/*****************************************************************************/
void saveKeyToEE(uint8_t keySlot, uint8_t *pKeyAuth)
{
	uint16_t keySize;
	uint8_t *pKeyData = &((TPM_return*) xferBuf)->payLoad;

	// parse the key structure to get key size
	// easier to "walk" a pointer than add all the variable sizes
	pKeyData += sizeof(keyFixed);								// 39
	pKeyData += convertArrayToLong(pKeyData-4);					// PCR size
	pKeyData += (4 + convertArrayToLong(pKeyData));				// store_pubKey
	pKeyData += (4 + convertArrayToLong(pKeyData));				// store_privKey

	keySize = pKeyData - &((TPM_return*) xferBuf)->payLoad;		// returns size in bytes

	printf("\r\nkeySize is %d", keySize); 
	printf("\r\nwriting key to NVM slot %d...", (keySlot+1));
	
// 	eeprom_write_block(&xferBuf[10], &keyStore[keySlot].keyData, keySize);
// 	eeprom_write_block(pKeyAuth, &keyStore[keySlot].keyAuth, sizeof(keyStore[keySlot].keyAuth));
// 	eeprom_write_word(&keyStore[keySlot].keySize, keySize);
// 	eeprom_write_byte(&keyStore[keySlot].keyValid, KEY_VALID);
	 

	nvm_write_block(&xferBuf[10], nvmAddr_KeyStore_t.keyData[keySlot], keySize);
 	nvm_write_block(pKeyAuth, nvmAddr_KeyStore_t.keyAuth[keySlot], sizeof(keyStore[keySlot].keyAuth));
 	nvm_write_word(nvmAddr_KeyStore_t.keySize[keySlot], keySize);
 	nvm_write_byte(nvmAddr_KeyStore_t.keyValid[keySlot], KEY_VALID);
		 
	printf("\r\nwriting done!");
	
}
/*****************************************************************************/
uint16_t getKeyFromEE(uint8_t keySlot, uint8_t *outBuf)
{
	uint16_t keySize;


// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == KEY_VALID)
// 	{
// 		keySize = eeprom_read_word(&keyStore[keySlot].keySize);
// 		eeprom_read_block(outBuf, &keyStore[keySlot].keyData, keySize);
// 	}
// 	else keySize = 0;

	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == KEY_VALID)
	{
		keySize = nvm_read_word(nvmAddr_KeyStore_t.keySize[keySlot]);
		nvm_read_block(outBuf, nvmAddr_KeyStore_t.keyData[keySlot], keySize);
	}
	else keySize = 0;


	return keySize;
}

bool keySlotValid(uint8_t keySlot)
{
// 	if(eeprom_read_byte(&keyStore[keySlot].keyValid) == KEY_VALID)
// 	return true;
// 	else
// 	return false;

	if(nvm_read_byte(nvmAddr_KeyStore_t.keyValid[keySlot]) == KEY_VALID)
		return true;
	else
		return false;

}

/*****************************************************************************/
uint8_t saveKeyHandle(uint8_t keySlot, uint8_t *pHandle)
{
	uint8_t handleSlot;
	uint8_t	authBuf[20];

// 	uint8_t handleSlot;
// 	uint8_t	authBuf[20];
// 
// 	for(handleSlot = 0; handleSlot < (sizeof(loadedKeyStore) / sizeof(loadedKeyStruct)); handleSlot++)
// 	{
// 		if(eeprom_read_byte(&loadedKeyStore[handleSlot].keyValid) != KEY_VALID)
// 		{
// 			// store TPM handle
// 			eeprom_write_block(	pHandle,
// 								&loadedKeyStore[handleSlot].keyHandle,
// 								sizeof(loadedKeyStore[handleSlot].keyHandle));
// 
// 			// store the key's auth data
// 			eeprom_read_block(authBuf, &keyStore[keySlot].keyAuth, sizeof(authBuf));
// 			
//			eeprom_write_block(	authBuf,
// 								&loadedKeyStore[handleSlot].keyAuth,
// 								sizeof(loadedKeyStore[handleSlot].keyAuth));
// 
// 			// update valid flag for handleSlot
// 			eeprom_write_byte(&loadedKeyStore[handleSlot].keyValid, KEY_VALID);
// 
// 			return handleSlot;
// 		}
// 	}
// 	return 0xFF;	// no available handleSlots
	
	
	
	for(handleSlot = 0; handleSlot < (sizeof(loadedKeyStore) / sizeof(loadedKeyStruct)); handleSlot++)
	{
		if(nvm_read_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot]) != KEY_VALID)
		{
			/* store TPM handle */
			nvm_write_block(pHandle,
							nvmAddr_loadedKeyStore_t.keyHandle[handleSlot],
							sizeof(loadedKeyStore[handleSlot].keyHandle));

			/* store the key's auth data */
			nvm_read_block(authBuf, nvmAddr_KeyStore_t.keyAuth[keySlot], sizeof(authBuf));
			
			nvm_write_block(authBuf,
							nvmAddr_loadedKeyStore_t.keyAuth[handleSlot],
							sizeof(loadedKeyStore[handleSlot].keyAuth));

			// update valid flag for handleSlot
			nvm_write_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot], KEY_VALID);

			return handleSlot;
		}
	}	
	
	return 0xFF;	// no available handleSlots
}
/*****************************************************************************/
bool flushKeyHandle(uint8_t handleSlot)
{
	// mark handleSlot invalid (flushing it)
	// should check valid and return status (later!!)
	//eeprom_write_byte(&loadedKeyStore[handleSlot].keyValid, KEY_INVALID);
	
	return (nvm_write_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot], KEY_INVALID));

}
/*****************************************************************************/
bool handleSlotValid(uint8_t handleSlot)
{
// 	if(eeprom_read_byte(&loadedKeyStore[handleSlot].keyValid) == KEY_VALID)
// 	return true;
// 	else
// 	return false;
	
	if(nvm_read_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot]) == KEY_VALID)
	 return true;
	else
	 return false;
	
	
}
/*****************************************************************************/
bool saveOwnerAuth(uint8_t *authBuf)
{
/*	eeprom_write_block(	authBuf, ownerAuthEE, sizeof(ownerAuthEE));*/
	return (nvm_write_block(authBuf, nvmAddr_var_t.ownerAuthEE, sizeof(ownerAuthEE)));
}
/*****************************************************************************/
bool saveSRKAuth(uint8_t *authBuf)
{
/*	eeprom_write_block(	authBuf, SRKAuthEE, sizeof(SRKAuthEE));*/
	return(nvm_write_block(authBuf, nvmAddr_var_t.SRKAuthEE, sizeof(SRKAuthEE)));
}
/*****************************************************************************/
bool getOwnerAuth(uint8_t *authBuf)
{
/*	eeprom_read_block( authBuf, ownerAuthEE, sizeof(ownerAuthEE));*/
	return (nvm_read_block( authBuf, nvmAddr_var_t.ownerAuthEE, sizeof(ownerAuthEE)));
}
/*****************************************************************************/
bool getSRKAuth(uint8_t *authBuf)
{
/*	eeprom_read_block( authBuf, SRKAuthEE, sizeof(SRKAuthEE));*/
	return (nvm_read_block( authBuf, nvmAddr_var_t.SRKAuthEE, sizeof(SRKAuthEE)));
}
/*****************************************************************************/
void initLoadedKeyStore(void)
{
//	uint8_t handleSlot;
// 	for(handleSlot = 0; handleSlot < (sizeof(loadedKeyStore) / sizeof(loadedKeyStruct)); handleSlot++)
// 	{
// 		// wipe valid flag for handleSlot
// 		nvm_write_byte(nvmAddr_loadedKey_t.keyValid[handleSlot], KEY_INVALID);
// 	}

uint8_t initVal[80] = { KEY_INVALID};
nvm_write_block(&initVal[0], nvmAddr_loadedKeyStore_t.keyValid[0], sizeof(initVal));

}
/*****************************************************************************/
void initKeyStore(void)
{
// 	uint8_t keySlot;
// 
// 	for(keySlot = 0; keySlot < (sizeof(keyStore) / sizeof(keyStoreStruct)); keySlot++)
// 	{
// 		// wipe valid flag for handleSlot
// 		eeprom_write_byte(&keyStore[keySlot].keyValid, KEY_INVALID);
// 	}


uint8_t initVal[20] = { KEY_INVALID};											
nvm_write_block(&initVal[0], nvmAddr_KeyStore_t.keyValid[0], sizeof(initVal));

}
/*****************************************************************************/
uint8_t getKnownKeyHandles(uint8_t *outBuf)
{
	uint8_t handleSlot, numLoadedKeys;

	for(handleSlot = 0, numLoadedKeys = 0;
	handleSlot < (sizeof(loadedKeyStore) / sizeof(loadedKeyStruct));
	handleSlot++ )
	{
		/* look for valid keys */
		if( nvm_read_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot]) == KEY_VALID)
		{
// 			eeprom_read_block( 	outBuf,
// 			&loadedKeyStore[handleSlot].keyHandle,
// 			sizeof(loadedKeyStore[handleSlot].keyHandle));
// 			outBuf += sizeof(loadedKeyStore[handleSlot].keyHandle);
// 			numLoadedKeys++;

			nvm_read_block( outBuf,
							nvmAddr_loadedKeyStore_t.keyHandle[handleSlot],
							sizeof(loadedKeyStore[handleSlot].keyHandle));
			
			outBuf += sizeof(loadedKeyStore[handleSlot].keyHandle);
			numLoadedKeys++;


		}
	}
	return numLoadedKeys;
}
/*****************************************************************************/
bool getLoadedKeyAuth(uint8_t handleSlot, uint8_t *outBuf)
{

// 	// check for valid handleSlot
// 	if( eeprom_read_byte(&loadedKeyStore[handleSlot].keyValid) != KEY_VALID)
// 	return false;
// 
// 	// read auth data
// 	eeprom_read_block( 	outBuf,
// 	&loadedKeyStore[handleSlot].keyAuth,
// 	sizeof(loadedKeyStore[handleSlot].keyAuth));
	
	/* check for valid handleSlot */
	if(nvm_read_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot]) != KEY_VALID)
		return false;

	/* read auth data */
	nvm_read_block( outBuf,
					nvmAddr_loadedKeyStore_t.keyAuth[handleSlot],
					sizeof(loadedKeyStore[handleSlot].keyAuth));	
	
	
	return true;
}
/*****************************************************************************/
bool getLoadedKeyHandle(uint8_t handleSlot, uint8_t *outBuf)
{

// 	// check for valid handleSlot
// 	if( eeprom_read_byte(&loadedKeyStore[handleSlot].keyValid) != KEY_VALID)
// 	return false;
// 
// 	// read key handle
// 	eeprom_read_block( 	outBuf,
// 	&loadedKeyStore[handleSlot].keyHandle,
// 	sizeof(loadedKeyStore[handleSlot].keyHandle));
	
	/* check for valid handleSlot */
	if( nvm_read_byte(nvmAddr_loadedKeyStore_t.keyValid[handleSlot]) != KEY_VALID)
	return false;

	/* read key handle */
	nvm_read_block(	outBuf,
					nvmAddr_loadedKeyStore_t.keyHandle[handleSlot],
					sizeof(loadedKeyStore[handleSlot].keyHandle));	
	
	return true;
}
/*****************************************************************************/
uint8_t findKeyHandle(uint32_t handleNumVar)
{
	uint8_t		handleSlot;
	uint8_t		handleBuf[4];

	for(handleSlot = 0; handleSlot < (sizeof(loadedKeyStore) / sizeof(loadedKeyStruct)); handleSlot++)
		if( handleSlotValid(handleSlot))
		{
			getLoadedKeyHandle(handleSlot, handleBuf);
			if(convertArrayToLong(handleBuf) == handleNumVar)
				return handleSlot;
		}

	return INVALID_HANDLE;
}

uint8_t nvm_write_byte(uint32_t *pdest, uint8_t value)
{
	return nvm_write(&value, pdest, 1);
}

uint8_t nvm_write_word(uint32_t *pdest, uint16_t value)
{
	uint8_t *p;
	union {
		uint8_t		bytes[2];
		uint16_t	val;
	} data;
	
	data.val = value;
	p = &data.bytes[0];	

	return nvm_write(p, pdest, 2);
}

uint8_t nvm_write_block(uint8_t *psrc, uint32_t *pdest, uint16_t size)
{
	return (nvm_write(psrc, pdest, size));	
}

uint8_t nvm_write(uint8_t *psrc, uint32_t *pdest, uint16_t size)
{
// 	static uint16_t buffer_offset = 0;
// 	static uint16_t i =0;
// 	static uint8_t rdata =0;
// 	static uint8_t x;
// 	static uint32_t ul_page_addr;
// 	static uint32_t ul_block_addr;
// 	static uint32_t *pul_block_addr;
// 	static uint32_t *pul_page_addr;
// 	static uint16_t pus_page;
// 	static uint16_t pus_offset;
// 	static uint32_t ul_idx;
// 	static uint32_t ul_page_buffer[785];//,2048 NVM_READ_BUFFER_WORD_SIZE
// 	static uint16_t region_overflow;
// 	static uint16_t write_size_inbytes;
// 	static uint8_t group_crossing_detected;
// 	static uint8_t update_read_buffer= 1;	
// 	static uint16_t pus_offset_inbytes;

 	uint32_t retCode;
	uint16_t buffer_offset = 0;
	uint16_t i =0;
	uint8_t rdata =0;
	uint8_t x;
	uint32_t ul_page_addr;
	uint32_t ul_block_addr;
	uint32_t *pul_block_addr;
	uint16_t pus_page;
	uint16_t pus_offset;
	uint32_t ul_idx;
	uint32_t ul_page_buffer[NVM_READ_HALF_BUFFER_WORD_SIZE]; //NVM_READ_FULL_BUFFER_WORD_SIZE
    Efc *pp_efc;
	
	/* determine current FLASH page  and offset */
	translate_address(&pp_efc, (uint32_t)pdest, &pus_page, &pus_offset);
	
	asm("nop");

	/* variable initialization */
	ul_block_addr			= 0x005FE000;

	/* determine uin32_t page address given FLASH page an offset */
	compute_address(pp_efc, pus_page, 0, &ul_page_addr);
	
	/* set block address */						
	pul_block_addr	= 	(uint32_t*)ul_block_addr;

	/* determine buffer offset */
	buffer_offset = (pus_page - 2032)*128;


	/* read the group current data ( 4K bytes) to buffer before erasing */
	for (ul_idx = 0; ul_idx < NVM_READ_HALF_BUFFER_WORD_SIZE /* NVM_READ_FULL_BUFFER_WORD_SIZE*/; ul_idx++) {
		ul_page_buffer[ul_idx] = pul_block_addr[ul_idx];
	}


	pus_offset = pus_offset >> 2;
		
	/* update page buffer w/ new data */
	for(i=0; i < (size / 4); i++)
	{
		ul_page_buffer[i + pus_offset + buffer_offset ]  = (*psrc++ <<24);
		ul_page_buffer[i + pus_offset + buffer_offset ] |= (*psrc++ << 16);
		ul_page_buffer[i + pus_offset + buffer_offset ] |= (*psrc++ << 8);
		ul_page_buffer[i + pus_offset + buffer_offset ] |= *psrc++;
	}

	/* load remaining data if any */
	rdata = (size % 4);
	if(rdata)
	{
		for(x=0; x < rdata; x++)
		{
			if(x == 0)
				ul_page_buffer[i + pus_offset + buffer_offset ]  =  (*psrc++ << 24);
			else
				ul_page_buffer[i + pus_offset + buffer_offset ] |=  (*psrc++ <<(24-(8*x)));
		}
	}


 	/* Unlock page */
	if(flash_unlock(ul_block_addr,ul_block_addr + IFLASH_PAGE_SIZE - 1, 0, 0) != FLASH_RC_OK){
		return 0;
	}

	/* The EWP command is not supported for non-8KByte sectors in all devices
		*  SAM4 series, so an erase command is required before the write operation.
		*/
	cpu_irq_enter_critical();
	retCode =  flash_erase_page(ul_block_addr, IFLASH_ERASE_PAGES_16);
	cpu_irq_leave_critical();
			
	if(retCode != FLASH_RC_OK){
		return 0;
	}	
	
	cpu_irq_enter_critical();
	retCode = flash_write(ul_block_addr, ul_page_buffer,NVM_READ_HALF_BUFFER_BYTE_SIZE /* NVM_READ_FULL_BUFFER_BYTE_SIZE*/, 0);
	cpu_irq_leave_critical();
		
	if( retCode != FLASH_RC_OK) {	
		return 0;
	}
	  
	/* Validate region */	
	for (ul_idx = 0; ul_idx < NVM_READ_HALF_BUFFER_WORD_SIZE /* NVM_READ_FULL_BUFFER_WORD_SIZE*/; ul_idx++) {
		if (pul_block_addr[ul_idx] != ul_page_buffer[ul_idx]) {
			return 0;
		}
	}

	/* Lock page */
	if(flash_lock(ul_block_addr,ul_block_addr + IFLASH_PAGE_SIZE - 1, 0, 0) != FLASH_RC_OK)
	{
		return 0;
	}

	delay_ms(10);
	return 1;

}


uint8_t nvm_read_byte(uint32_t *psrc)
{
	uint8_t value = 0;
	nvm_read(&value, psrc, 1);
	return value;
}

uint16_t nvm_read_word(uint32_t *psrc)
{
	union {
		uint8_t		bytes[2];
		uint16_t	value;
	} param;
	
	nvm_read(&param.bytes[0], psrc, 2);

	return param.value;
}


uint8_t nvm_read_block(uint8_t *pdest, uint32_t *psrc, uint16_t size)
{
	return nvm_read(pdest, psrc, size);
}


uint8_t nvm_read(uint8_t *pdest, uint32_t *psrc, uint16_t size)
{
	uint8_t  x;
	uint8_t  rdata =0;
	uint32_t ul_idx;
 	uint32_t ul_base_page_addr;
 	uint32_t *pul_base_page_addr;
	uint16_t pus_page;
	uint16_t pus_offset;
	
	Efc *pp_efc;	
	ul_idx = 0;
	
	/* determine current FLASH page  and offset */
	translate_address(&pp_efc, (uint32_t)psrc, &pus_page, &pus_offset);
	
	/* determine uin32_t page address given FLASH page an offset */
	compute_address(pp_efc, pus_page, 0, &ul_base_page_addr);
	
	pul_base_page_addr		=   (uint32_t*)ul_base_page_addr;
	
	pus_offset = pus_offset >> 2;

	/* update page buffer w/ new data */
	/* size in bytes */
	for(ul_idx = 0; ul_idx < (size / 4); ul_idx++)
	{
		*pdest++ = (pul_base_page_addr[ul_idx + pus_offset ] >> 24);
		*pdest++ = (pul_base_page_addr[ul_idx + pus_offset ] >> 16);
		*pdest++ = (pul_base_page_addr[ul_idx + pus_offset ] >> 8);
		*pdest++ = (pul_base_page_addr[ul_idx + pus_offset]);
	}


	/* load remaining data if any */
	rdata = size % 4;
	if(rdata)
	{
		for(x=0; x < rdata; x++)
		{
			if(x == 0)
				*pdest++ = (pul_base_page_addr[ul_idx + pus_offset] >> 24);
			else
				*pdest++ = (pul_base_page_addr[ul_idx + pus_offset] >> (24-(8*x)));
		}
	}

	return 1;

}


/*****************************************************************************/
void nvm_unit_test()
{

	uint8_t retCode=0;
	uint8_t testSetup[] = { /* 512 bYTES */
		
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
		0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
	};
	
	
	uint8_t testBuffer3[] = { /* 613 bYTES */
		
		//0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0x00, 0xC5, 0x00, 0x00, 0x00, 0x02, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x11,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,

		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,

		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x1B,
		
		
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0x2B,
		
		/* remaining buffer content */
		0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0x3B,

		
	};

	
/* GROUP 1 TEST */
retCode  = nvm_setup(testSetup,(uint32_t *) 0x005FE000, sizeof(testSetup));
asm("nop");
	 
retCode = nvm_write_block(&testBuffer3[0],(uint32_t*)0x005FEC00, sizeof(testBuffer3));
asm("nop");
}


uint8_t nvm_setup(uint8_t *psrc, uint32_t *pdest, uint16_t size)
{
	uint16_t i =0;
	uint8_t rdata =0;
	uint8_t x;
	uint32_t ul_page_addr;

	static uint32_t ul_page_buffer[IFLASH_PAGE_SIZE / sizeof(uint32_t)];
	static uint16_t pus_page;
	static uint16_t pus_offset;


    Efc *pp_efc;	

	translate_address(&pp_efc, (uint32_t)pdest, &pus_page, &pus_offset);
	compute_address(pp_efc, pus_page, 0, &ul_page_addr);
	
			
			
	pus_offset = pus_offset >> 2;

	/* update page buffer w/ new data */
	for(i=0; i < (size / 4); i++)
	{
		ul_page_buffer[i ]  = (*psrc++ <<24);
		ul_page_buffer[i] |= (*psrc++ << 16);
		ul_page_buffer[i] |= (*psrc++ << 8);
		ul_page_buffer[i] |= *psrc++;
	}

	/* load remaining data if any */
	rdata = (size % 4);
	if(rdata)
	{
		for(x=0; x < rdata; x++)
		{
			if(x == 0)
				ul_page_buffer[i]  =  (*psrc++ << 24);
			else
				ul_page_buffer[i] |=  (*psrc++ <<(24-(8*x)));
		}
	}
		
		
			
	/* Unlock page */
	if(flash_unlock(ul_page_addr,ul_page_addr + IFLASH_PAGE_SIZE - 1, 0, 0) != FLASH_RC_OK){
		return 0;
	}

	/* The EWP command is not supported for non-8KByte sectors in all devices
	 *  SAM4 series, so an erase command is required before the write operation.
	 */
	if(flash_erase_sector(ul_page_addr)  != FLASH_RC_OK){
		return 0;
	}


	/* write all 4 pages */
	
	for(i=0; i < 16; i++)
	{

		if(flash_write(ul_page_addr, ul_page_buffer,IFLASH_PAGE_SIZE, 0)  != FLASH_RC_OK) {
			return 0;
		}
			
		pus_page++;
		compute_address(pp_efc, pus_page, 0, &ul_page_addr);
		
	}

	

// 	/* Validate page */
// 	for (ul_idx = 0; ul_idx < (IFLASH_PAGE_SIZE / 4); ul_idx++) {
// 		if (pul_last_page[ul_idx] != ul_page_buffer[ul_idx]) {
// 			asm("nop");
// 			return 0;
// 		}
// 	}
//
// 	/* Lock page */
// 	if(flash_lock(ul_page_addr,
// 	ul_page_addr + IFLASH_PAGE_SIZE - 1, 0, 0) != FLASH_RC_OK)
// 	{
// 		asm("nop");
// 		return 0;
// 	}


	return 1;

}


