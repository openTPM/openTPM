#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <asf.h>

#include "utils.h"
//#include "main.h"
#include "commandStructs.h"

#include "globals.h"
#include "hashFuncs.h"
//#include "UART.h"
#include "physical.h"
#include "authHandler.h"


uint8_t inAuthHandler(uint8_t numAuths, uint8_t numInHandles)
{

	uint16_t	authHandle1_offset, authHandle2_offset, payloadStart_offset;
	uint16_t	bytesToHash;

	authHandle1_offset = authHandle2_offset = payloadStart_offset = 0;

	hashContext *ctx = (hashContext*) workBuf3;

	printf("\r\n\r\ninAuthHandler...");
	
    printf("\r\n    numAuths: %d", numAuths);
 	 
 
 	printf("\r\n    numInHandles: %d", numInHandles);
	

	// figure out where the auth handle(s) are...
	switch (numAuths) {

		case 0:
			return 0;
		case 1:
			authHandle1_offset = numBytes - AUTH1_SIZE;
			
			printf("\r\n    authHandle1_offset: %d", authHandle1_offset);
			

			break;
		case 2:
			authHandle1_offset = numBytes - AUTH2_SIZE;
			authHandle2_offset = numBytes - AUTH1_SIZE;
			
 			printf("\r\n    authHandle1_offset: %d", authHandle1_offset); 
			

 			printf("\r\n    authHandle2_offset: %d", authHandle2_offset);
			
			break;
		default:
		
			printf("\r\n    illegal numAuths: %d", numAuths);
			
			return -1;
	};

	// figure out where the input digest starts...
	switch (numInHandles) {

		case 0:
			payloadStart_offset =  PAYLOAD_START_OFF;
			break;
		case 1:
			payloadStart_offset =  PAYLOAD_START_OFF + HAND1_SIZE;
			break;
		case 2:
			payloadStart_offset =  PAYLOAD_START_OFF + HAND2_SIZE;
			break;
		default:
			printf("\r\n    illegal numInHandles: %d", numInHandles); 
				
			return -1;
	};

	printf("\r\n    payloadStart_offset: %d", payloadStart_offset); 
	

	// calculate bytesToHash
	bytesToHash = numBytes - (numAuths * SZ_INAUTH) - payloadStart_offset;
	printf("\r\n    bytesToHash(1): %d\r\n", bytesToHash);
	

	// grab the ordinal for output auth calculation
	memmove( ordinal, &xferBuf[ORD_OFFSET], sizeof(ordinal) );

	// now do the input digest
	sha1_start( ctx );
	sha1_update( ctx, ordinal, sizeof(ordinal) );					// always do the ordinal
	sha1_update( ctx, &xferBuf[payloadStart_offset], bytesToHash );	// rest of payload
	sha1_finish( ctx, HMACBuf.paramDigest );

	// setup the HMAC calculation
	memmove(HMACBuf.nonceEven, authSessions[0].nonceEven, sizeof(HMACBuf.nonceEven));
	memmove(HMACBuf.nonceOdd, authSessions[0].nonceOdd, sizeof(HMACBuf.nonceOdd) );
	HMACBuf.contAuth = 0x00;  	// this should be set by the caller...

	// now do the HMAC
	sha1_hmac(	authSessions[0].HMACKey,
				sizeof(authSessions[0].HMACKey),
				(uint8_t*) &HMACBuf,
				sizeof(HMACBuf),
				workBuf2
			  );

	// display the HMAC parameters
	dumpHMACparms(0, workBuf2);

	// now assemble all the auth data for transmission to TPM

	// copy the authHandle to xferBuf
	memmove(&xferBuf[authHandle1_offset], authSessions[0].handle, SZ_HAND);

	// copy the oddNonce to xferBuf
	memmove(&xferBuf[authHandle1_offset+SZ_HAND], HMACBuf.nonceOdd, sizeof(HMACBuf.nonceOdd));

	// set the continueAuth flag
	xferBuf[authHandle1_offset+SZ_HAND+20] = HMACBuf.contAuth;

	// copy the HMAC to xferBuf
	memmove(&xferBuf[authHandle1_offset+SZ_HAND+20 + 1], workBuf2, 20);

	// deal with second authSession if present
	if(numAuths == 2)
	{
		// setup the HMAC calculation
		memmove(HMACBuf.nonceEven, authSessions[1].nonceEven, sizeof(HMACBuf.nonceEven));
		memmove(HMACBuf.nonceOdd, authSessions[1].nonceOdd, sizeof(HMACBuf.nonceOdd) );
		HMACBuf.contAuth = 0x00;  	// this should be set by the caller...

		// now do the HMAC
		sha1_hmac(	authSessions[1].HMACKey,
					sizeof(authSessions[1].HMACKey),
					(uint8_t*) &HMACBuf,
					sizeof(HMACBuf),
					workBuf2 );

		// display the HMAC parameters
		dumpHMACparms(1, workBuf2);

		// now assemble all the auth data for transmission to TPM

		// copy the authHandle to xferBuf
		memmove(&xferBuf[authHandle2_offset], authSessions[1].handle, SZ_HAND);

		// copy the oddNonce to xferBuf
		memmove(&xferBuf[authHandle2_offset+SZ_HAND], HMACBuf.nonceOdd, sizeof(HMACBuf.nonceOdd));

		// set the continueAuth flag
		xferBuf[authHandle2_offset+SZ_HAND+20] = HMACBuf.contAuth;

		// copy the HMAC to xferBuf
		memmove(&xferBuf[authHandle2_offset+SZ_HAND+20 + 1], workBuf2, 20);
	}

	// dump what we're about to send
//	dumpXferBuf();

	return 0;
}
/*******************************************************************************************/
// checks output HMAC, updates authSession even nonce(s)
uint8_t outAuthHandler(uint8_t numAuths, uint8_t numOutHandles)
{
	uint16_t	paramSize, bytesToHash, payloadStart_offset;
	uint16_t	authSessionOffset;
	outAuth		*poutAuth;
	hashContext *ctx = (hashContext*) workBuf3;
	TPM_return	*pTPM_return = (TPM_return*) xferBuf;
	bool		passFlag = true;

	printf("\r\noutAuthHandler...");
	
	printf("\r\n    numAuths: %d", numAuths); 
	
	
 	printf("\r\n    numOutHandles: %d", numOutHandles);
	

	// grab paramSize for later use
	paramSize = convertArrayToLong(pTPM_return->paramSize);

	// figure out where the payload starts...
	switch (numOutHandles) {

		case 0:
			payloadStart_offset =  PAYLOAD_START_OFF;
			break;
		case 1:
			payloadStart_offset =  PAYLOAD_START_OFF + HAND1_SIZE;
			break;
		case 2:
			payloadStart_offset =  PAYLOAD_START_OFF + HAND2_SIZE;
			break;
		default:
			printf("\r\n    illegal numOutHandles: %d", numOutHandles);
			
			return -1;
	};

	printf("\r\n    payloadStart_offset: %d", payloadStart_offset);
	

	// calculate bytesToHash
	bytesToHash = numBytes - payloadStart_offset - SZ_OUTAUTH * numAuths;
	printf("\r\n    bytesToHash(2): %d\r\n", bytesToHash);
	

	// now do the output digest -- used for all auth calculations
	sha1_start( ctx );
	sha1_update( ctx, pTPM_return->returnCode, sizeof(pTPM_return->returnCode) );		// return code
	sha1_update( ctx, ordinal, sizeof(ordinal) );										// ordinal
	sha1_update( ctx, &pTPM_return->payLoad, bytesToHash );								// rest of payload
	sha1_finish( ctx, HMACBuf.paramDigest );

	/********************************
	 * authSession[0] calculations	*
	 ********************************/

	// setup authSession[0] overlay
	authSessionOffset = paramSize - numAuths * SZ_OUTAUTH;
	poutAuth = (outAuth*) &xferBuf[authSessionOffset];

	// grab the new nonceEven from the TPM output
	memmove(	authSessions[0].nonceEven,
				poutAuth->nonceEven,
				sizeof(authSessions[0].nonceEven) );

	// setup the HMAC calculation for authSession[0]
	memmove(HMACBuf.nonceEven, authSessions[0].nonceEven, sizeof(HMACBuf.nonceEven));
	memmove(HMACBuf.nonceOdd, authSessions[0].nonceOdd, sizeof(HMACBuf.nonceOdd) );
	HMACBuf.contAuth = poutAuth->contAuth;

	// now do the authSession[0] HMAC
	sha1_hmac(	authSessions[0].HMACKey,
				sizeof(authSessions[0].HMACKey),
				(uint8_t*) &HMACBuf,
				sizeof(HMACBuf),
				workBuf2
			  );

	// display the HMAC parameters
	dumpHMACparms(0, workBuf2);

	// validate the output HMAC
	printf("\r\nauthSession[0] HMAC validation ");
	if( memcmp(workBuf2, poutAuth->HMACout, sizeof(poutAuth->HMACout)) )
	{
		printf("failed");
		passFlag = false;
	}
	else
		printf("passed");

	printf("\r\n");

	if(numAuths == 2)
	{
		/********************************
		 * authSession[1] calculations	*
		 ********************************/

	// setup authSession[1] overlay
	authSessionOffset = paramSize - (numAuths-1) * SZ_OUTAUTH;
	poutAuth = (outAuth*) &xferBuf[authSessionOffset];

	// grab the new nonceEven from the TPM output
	memmove(	authSessions[1].nonceEven,
				poutAuth->nonceEven,
				sizeof(authSessions[1].nonceEven) );

	// setup the HMAC calculation for authSession[1]
	memmove(HMACBuf.nonceEven, authSessions[1].nonceEven, sizeof(HMACBuf.nonceEven));
	memmove(HMACBuf.nonceOdd, authSessions[1].nonceOdd, sizeof(HMACBuf.nonceOdd) );
	HMACBuf.contAuth = 0x00;  	// this should be set by the caller...

	// now do the authSession[1] HMAC
	sha1_hmac(	authSessions[1].HMACKey,
				sizeof(authSessions[1].HMACKey),
				(uint8_t*) &HMACBuf,
				sizeof(HMACBuf),
				workBuf2
			  );

	// display the HMAC parameters
	dumpHMACparms(1, workBuf2);

		// validate the output HMAC
		printf( "\r\nauthSession[1] HMAC validation ");
		if( memcmp(workBuf2, poutAuth->HMACout, sizeof(poutAuth->HMACout)) )
		{
			printf("failed");
			passFlag = false;
		}
		else
			printf("passed");
	}

	printf("\r\n");

	return passFlag = true ? false : true; 	// invert sense
}

// calculate an encAuth value in place - encAuth points to input auth
void encAuthHandler(uint8_t *pNonce, uint8_t *pHMACkey, uint8_t *encAuth)
{

	uint8_t	xorBuf[20];
	uint8_t	i;
	hashContext *ctx = (hashContext*) workBuf3;

	printf("\r\nencAuthHandler ...");

	printf("\r\n    nonce:       ");
	for(i=0;i<SZ_DIGEST;i++) 
		printf("%02X ", pNonce[i]);

	printf("\r\n    secret:      ");
	for(i=0;i<SZ_DIGEST;i++) 
		printf("%02X ", pHMACkey[i]);

	// generate xor mask
	sha1_start( ctx );
	sha1_update( ctx, pHMACkey, SZ_DIGEST );
	sha1_update( ctx, pNonce, SZ_DIGEST );
	sha1_finish( ctx, xorBuf );

	printf("\r\n    xor mask:    ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", xorBuf[i]);

	printf("\r\n    encAuth in:  ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", encAuth[i]);

	// create encAuth in place
	for (i=0; i<SZ_DIGEST; i++)
		encAuth[i] ^= xorBuf[i];

	printf("\r\n    encAuth out: ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", encAuth[i]);

}

void dumpHMACparms(uint8_t numAuthSession, uint8_t *HMACoutBuf)
{
	uint8_t		i;

	// display the HMAC parameters
	printf("\r\n    authSession[%d] HMAC calculation:", numAuthSession);

	printf("\r\n    param digest:  ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", HMACBuf.paramDigest[i]);

	printf("\r\n    nonceEven:     ");
 	for(i=0;i<SZ_DIGEST;i++)
 		printf("%02X ", HMACBuf.nonceEven[i]);

	printf("\r\n    nonceOdd:      ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", HMACBuf.nonceOdd[i]);

	printf("\r\n    contAuth:      ");
	printf("%02X ", HMACBuf.contAuth);

	printf("\r\n    HMACKey:       ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", authSessions[numAuthSession].HMACKey[i]);

	printf("\r\n    HMAC output:   ");
	for(i=0;i<SZ_DIGEST;i++)
		printf("%02X ", HMACoutBuf[i]);

	printf("\r\n");
}
