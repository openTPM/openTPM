#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

//#include "main.h" kmj
#include "TPM_errors.h"
#include "commandStructs.h"
#include "nvStoreFuncs.h"
#include "globals.h"
#include "hashFuncs.h"
#include "physical.h"
#include "authHandler.h"
#include "utils.h"
#include "commandfuncs.h"
void uart_usb_flush(void);
void usb_task(void);


/*****************************************************************************************************/
void resetTPM(void)
{
	
//	kmj
// 	uint16_t delay;
// 
// 	DDRA |= 0x01;	// all inputs except PRA 0
// 
// 	// generate a TPM reset pulse (low active)
// 	PORTA &= ~0x01;
// 
// 	for(delay=0; delay < 1000; delay++) 
// 		/* do nothing */;
// 
// 	PORTA |= 0x01;	// leave deasserted

}	
/*****************************************************************************************************/
//void OSAPHandler( void *pCommand )
void OSAPHandler( TPM_Command *pCommand )
{
	// starts an OSAP session, storing the OSAP parms in authSession[currentAuthSession]

	// setup overlays for OSAP parameters
	OSAPIn	*pOSAPIn = (OSAPIn*) xferBuf;
	OSAPOut	*pOSAPOut = (OSAPOut*) xferBuf;
	OSAPHashBuf *pOSAPHashBuf = (OSAPHashBuf*) workBuf0;

	// OSAP template is in xferBuf, setup the incoming OSAP parameters
	memmove(pOSAPIn->entityType, OSAPparms.entityType, sizeof(pOSAPIn->entityType));
	memmove(pOSAPIn->entityValue, OSAPparms.entityValue, sizeof(pOSAPIn->entityValue));

	// get an OSAPNonceOdd, save a copy for later
	getNonceOdd(pOSAPIn->nonceOddOSAP, fixedNonce);
	memmove(pOSAPHashBuf->nonceOddOSAP, pOSAPIn->nonceOddOSAP, sizeof(pOSAPHashBuf->nonceOddOSAP));

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// abort on error
//	if(convertArrayToLong(&xferBuf[6]) != TPM_SUCCESS)
	if(convertArrayToLong(pOSAPOut->returnCode) != TPM_SUCCESS)
		return;

	// retrieve OSAPNonceEven from TPM output
	memmove(pOSAPHashBuf->nonceEvenOSAP, pOSAPOut->nonceEvenOSAP, sizeof(pOSAPHashBuf->nonceEvenOSAP));

	// now do the hmac to create the session shared secret
	sha1_hmac(	OSAPparms.entityAuth,
				sizeof(OSAPparms.entityAuth),
				(uint8_t*) pOSAPHashBuf,
				sizeof(OSAPHashBuf),
				authSessions[currentAuthSession].HMACKey
			 );

	// save the session authHandle
	memmove(authSessions[currentAuthSession].handle, pOSAPOut->authHandle, sizeof(pOSAPOut->authHandle));

	// save the session nonceEven
	memmove(authSessions[currentAuthSession].nonceEven, pOSAPOut->nonceEven, sizeof(pOSAPOut->nonceEven));

}
/*****************************************************************************************************/
// uses 0xA5 if not real randoms
void getRandomNum(uint8_t *dest, uint16_t count, randType randFlag)
{
	uint8_t	randBuf[4];
	//uint16_t numBytes;

	if( randFlag == realRandom)
	{
		for(numBytes = 0; numBytes+4 < count; numBytes+=4)
		{
			//convertLongToArray(random(), &dest[numBytes]); rt todo, implement this
		}

		// remaining bytes
		if(numBytes < count)
		{
			//convertLongToArray(random(), randBuf);		 rt todo, implement this
			memmove(&dest[numBytes], randBuf, count - numBytes);
		}
	}
	else
	{
        memset(dest, 0xA5, count);
	}
}
/*****************************************************************************************************/
// uses nonceC if not real randoms
void getNonceOdd(uint8_t *dest, nonceType nonceFlag)
{
	if( nonceFlag == realNonce)
	{
        getRandomNum(dest, SZ_DIGEST, realRandom);
	}
	else
	{
		//memcpy_P(dest, nonceC, SZ_DIGEST);
		memcpy(dest, nonceC, SZ_DIGEST);
	}
}
/*****************************************************************************************************/
// converts uint32 to MSB array
void convertLongToArray(uint32_t inVal, uint8_t *addr)
{
    *addr++ = (char)((inVal & 0xFF000000) >> 24);
    *addr++ = (char)((inVal & 0x00FF0000) >> 16);
    *addr++ = (char)((inVal & 0x0000FF00) >> 8);
    *addr = (char)(inVal & 0x000000FF);
}
/*****************************************************************************************************/
// converts uint16 to MSB array
void convertIntToArray(uint16_t inVal, uint8_t *addr)
{
    *addr++ = (char)((inVal & 0xFF00) >> 8);
    *addr = (char)(inVal & 0x00FF);
}
/*****************************************************************************************************/
// converts 4 byte MSB ordered array to uint32
uint32_t convertArrayToLong( uint8_t *addr )
{
    struct ul {
        uint8_t uc1;
        uint8_t uc2;
        uint8_t uc3;
        uint8_t uc4;
    };

    union ulu {
        struct ul sul;
        uint32_t longvar;
    } theUnion;

    // Align The Individual Bytes In The Proper Order
    theUnion.sul.uc4 = *addr++;
    theUnion.sul.uc3 = *addr++;
    theUnion.sul.uc2 = *addr++;
    theUnion.sul.uc1 = *addr;

    // Return The Value As A Unsigned Long
    return( theUnion.longvar );
}
/*****************************************************************************************************/
//  converts 2 byte MSB ordered array to uint16
uint16_t convertArrayToInt( uint8_t *addr )
{
    uint32_t valueShort;

   // Align The Individual Bytes In The Proper Order
   valueShort = 0x00;
   valueShort |= (*addr++) << 8;
   valueShort |= *addr;

   // Return The Value As A Unsigned Int
   return( valueShort );
}
/*****************************************************************************************************/
void showKnownKeys(void)
{
	uint16_t	numLoadedKeys;
	uint8_t 	(*pHandle)[SZ_HAND];
	uint8_t		i;

	numLoadedKeys = getKnownKeyHandles(workBuf0);
	if( numLoadedKeys != 0 )
	{
		pHandle = (uint8_t (*)[SZ_HAND]) workBuf0;
		printf("\r\n\r\n    known keyHandles:");
		for(i=0; i < numLoadedKeys; i++)
		{
			printf("\r\n        %d: ", (i+1) );
			printf("%02X %02X %02X %02X",
						pHandle[i][0], pHandle[i][1],
						pHandle[i][2], pHandle[i][3] );
		}
	}
	else
	{
		
		printf("\r\n\r\nNo loaded keys to display");
	}

	printf("\r\n\r\npress any key to continue...");
	scanf("%c", &i);
}
/*****************************************************************************************************/
uint8_t	selectHandleSlot(uint8_t *workBuf, char* promptSTR, SRKopt SRKflag)
{
	uint16_t	i, j, numLoadedKeys;
	int 		slotNum, selectNum;
	bool		validOption;
	

	// it can't be assumed that all handle slots are valid or contiguous since keys could
	// have been subsequently flushed; it is always necessary to call findKeyHandle on
	// the user's selection to get the correct handle slot

	// let the user pick a parent key if any are available
	validOption = false;
	numLoadedKeys = getKnownKeyHandles(workBuf);	// fills workBuf with packed array of valid handles

	if( (numLoadedKeys == 0) && (SRKflag == excludeSRK) )
	{
		printf("\r\n    no known keys!\r\n");
		printf("\r\n    aborting...\r\n" );
		return INVALID_HANDLE;
	}

	if( numLoadedKeys != 0 )
	{
		while( validOption == false )
		{
			printf("\r\n    known keyHandles:" );
			for(i=0; i < numLoadedKeys; i++)
			{
				printf("\r\n        %d: ", (i+1) ); 
				for(j = i*SZ_HAND; j < i*SZ_HAND + SZ_HAND; j++)
					printf( "%02X ", workBuf[j] );
			}

			// prompt for the selection
			printf(promptSTR );
			
			//scanf("%d*", &selectNum);
			get_user_input(NULL,0,&selectNum, USER_NUM);

			if( (selectNum == 0) && (SRKflag == includeSRK) )			// SRK
				return selectNum;

			// get the slot associated with this selection
			else if( (slotNum = findKeyHandle(convertArrayToLong(&workBuf[(selectNum-1)*SZ_HAND]))) == INVALID_HANDLE)
			{
				printf("\r\n    invalid key number" );
				printf( "\r\n    aborting...\r\n" );
				return INVALID_HANDLE;
			}
			else
			{
				slotNum++;				// account for 1-based selection
				validOption = true;
			}
		}
	}
	else slotNum = 0;	// no keys loaded yet, must use SRK as parent

	return slotNum;
}

// wrappers for printf that automatically flush (for CDC USB)
/*****************************************************************************************************/



/*****************************************************************************************************/
// flushes backspaces
void flushBS(char *bufp)
{
	char *cp;

	// flush backspaces from input
	while( (cp = strchr(bufp, BS_CHAR)) )
		memmove(cp-1, cp+1, strlen(cp));
}
/*****************************************************************************************************/


void send_usb(uint16_t nb_data, char *buffer)
{
//	kmj
// 	uint16_t i;
// 
// 	// Transfer UART RX fifo to CDC TX
// 	if (!udi_cdc_is_tx_ready()) {
// 		// Fifo full
// 		udi_cdc_signal_overrun();
// 		ui_com_overflow();
// 	}
// 	else {
// 
// 		for(i =0; i<nb_data;i++ ){
// 			udi_cdc_putc(*buffer++);
// 		}
// 	}
// 	
// 	ui_com_tx_stop();

}