#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <asf.h>

#include "utils.h"
#include "commandFuncs.h"
#include "commandStructs.h"

#include "nvStoreFuncs.h"
#include "authHandler.h"
#include "authHandler.h"
#include "hashFuncs.h"
#include "TCG_tpm.h"
#include "TPM_errors.h"
#include "physical.h"
#include "globals.h"

void 	uart_usb_flush(void);
extern unsigned char tx_counter;

/*****************************************************************************************************/
void printCommand(char *commandName)
{
	TPM_Command *pCommand;
	uint16_t 	i, j;
	//char	buf[INBUFSIZE]; kmj

	
	for(i=0; i < numCommands; i++)
	{
		pCommand = &commandTable[i];
		if(! (strcmp(commandName, (char *) pCommand->commandName )) )
		{
			//sprintf(buf,"\r\n%s", (char *) pCommand->commandName);
			//printf(buf);kmj
			printf("\r\n%s", (char *) pCommand->commandName);
			printf("\r\ncommandSize: %d", pCommand->commandSize); 
			printf("\r\nnumAuths: %d", pCommand->numAuths);
			printf("\r\nnumInHandles: %d", pCommand->numInHandles);
			printf("\r\nnumOutHandles: %d", pCommand->numOutHandles);
			for(j=0; j < pCommand->commandSize; j++)
			{
				if(!(j % 16))
					printf("\r\n");
					
				//printf("%02X "), pgm_read_byte( (uint16_t) &pCommand->commandBytes[j]) ); kmj
			}

			printf("\r\n");
			return;
		}
	}
	
	//sprintf(buf,"\r\nunknown command: %s\r\n", commandName);
	//printf(buf); kmj
	printf("\r\nunknown command: %s\r\n", commandName);
	
}

/*****************************************************************************************************/
void listCommands(void)
{
// 	TPM_Command *pCommand;
// 	uint16_t 	i;
// 	char	nameBuf[20];
// 
// 	// display commands
// 	printf("\r\nnumber of commands: %d", numCommands);
// 	
// 	
// 	printf( ("\r\nsize of TPM_Command: %d"), sizeof(TPM_Command));
// 	
// 	
// 	printf( ("\r\nsize of commandTable: %d"), commandTableSize);
// 	
// 
// 	printf("\r\n\r\ncommand list:\r\n");
// 	for(i=0; i < numCommands; i++)
// 	{
// 		pCommand = &commandTable[i];
// 		strcpy(nameBuf, ("  "));
// 		strcat(nameBuf, (char*) pCommand->commandName);
// 		
// 		printf( ("%s\r\n"), nameBuf);
// 		
// 	}
}

TPM_Command *findCommand(const char *commandName)
{
	TPM_Command *pCommand;
	uint16_t	i;

	for(i=0; i < numCommands; i++)
	{
		pCommand = &commandTable[i];
		if(! (strcmp(commandName, (char*) pCommand->commandName )) )
			return pCommand;
	}
	/* not found... */
	return (TPM_Command *) NULL;
}


TPM_FuncPtr *findFuncPtr(const char *commandName)
{
	TPM_FuncPtr *pFuncPtr;
	uint16_t	i;

	for(i=0; i < numCommands; i++)
	{
		pFuncPtr = &FuncPtrTable[i];
		if(! (strcmp(commandName, (char*) pFuncPtr->commandName )) )
		return pFuncPtr;
	}
	/* not found... */
	return (TPM_FuncPtr *) NULL;
}

/*****************************************************************************************************/
void init_xferbuf()
{
	uint16_t	i;
	for(i=0; i<sizeof(xferBuf); i++)
		xferBuf[i]=0;
}
/*****************************************************************************************************/


bool commandHandler(const char* commandName)
{
	TPM_Command *pCommand;
	TPM_FuncPtr *pFuncPtr;
	uint32_t	errCode =0;
	
	funcPtr		commandFunc;
 	bool 		returnVal =0;
	uint8_t		i; 
	
	//Command called: TPM_Startup_Clear
	/*
	startupClear	-> TPM_Startup(Clear)
	contSelfTest	-> TPM_ContinueSelfTest
	createEKPair	-> TPM_CreateEndorsementKeyPair
	TPM_GetCap		-> TPM_GetCapability(PROP_OWNER)
	readEK			-> TPM_ReadPubEK
	OIAP            -> TPM_OIAP
	Takeownfun		-> TPM_TakeOwneship –also add printf before call- “Taking Ownership. Please wait……”
	*/
	
	/* special cases, print user friendly name,... definitely redo code */
	if(strcmp(commandName,"TPM_GetCap_PROP_OWNER")== 0)
		printf("\r\n\r\nCommand called: TPM_GetCap(PROP_OWNER)" );
	else if (strcmp(commandName,"contSelfTest")== 0)
		printf("\r\n\r\nCommand called: TPM_ContinueSelfTest" );
	else if (strcmp(commandName,"createEKPair")== 0)
		printf("\r\n\r\nCommand called: TPM_CreateEndorsementKeyPair" );	 
	else if (strcmp(commandName,"readEK")== 0)
		printf("\r\n\r\nCommand called: TPM_ReadPubEK" );
	else if (strcmp(commandName,"OIAP")== 0)
		printf("\r\n\r\nCommand called: TPM_OIAP" );	
	else if (strcmp(commandName,"takeOwnership")== 0)
	{
		printf("\r\n\r\nCommand called: TPM_TakeOwneship" );
		printf("\r\nTaking Ownership. Please wait... ");	
	}		 
	else
 	 printf("\r\n\r\nCommand called: %s", commandName );
	
	
	if( (pCommand = findCommand(commandName)) == NULL )
	{
		printf("\r\ncommand not found: %s", commandName );	
		return false;
	}
 	
	if( (pFuncPtr = findFuncPtr(commandName)) == NULL )
	{
		printf("\r\ncommand not found: %s", commandName );
		return false;
	}
	 
 	init_xferbuf();
 
 	/* load xferBuf with command data */	
	memcpy(&xferBuf[0],pCommand->commandBytes,pCommand->commandSize);		

	/* set numBytes */
	numBytes = pCommand->commandSize;

	/* call command function */
    commandFunc = (funcPtr) pFuncPtr->commandFunc;
    commandFunc(pCommand);

	/* check for TPM error responses */
	if(convertArrayToLong(((TPM_return*) xferBuf)->returnCode)  != TPM_SUCCESS )
	{
		printf("\r\n%s failed!" , commandName);
		error_notification(pCommand);
		returnVal = true;
	}
	else
	{
		 /* POST Processing */
		 printf("\r\nTPM_SUCCESS");
		 //printf("\r\ndone!");
		 
		success_post_processing(pCommand);
		returnVal = false;
	}
 
	printf("\r\npress any key to continue...");
	scanf( ("%c"), &i);

	return returnVal;
}

/*****************************************************************************************************/


void genericFunc( TPM_Command *pCommand )
{
	// generic send/receive routine (generally used for 0Auth commands)
	// can also be used for compliance mode (fixed) vectors
	// printf("\r\n    genericFunc called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

}
/*****************************************************************************************************/
void takeOwnFunc( TPM_Command *pCommand )
{
	// meta function to take ownership
	// expects chip to be cleared (no owner)
	// will generate EK if needed
	// fixme!  get rid of magic numbers...

	uint8_t authBuf[INBUFSIZE];
	uint8_t complianceFlag, compPubEKBuf[16];
	static int len;
	

	printf("\r\n    takeOwnFunc sequence:");
	
	// check for previous owner
	if(commandHandler("TPM_GetCap_PROP_OWNER"))
	{
		// if ekGen fails, then abort
		printf("\r\n   can't get tpm capability\r\n");
		printf("\r\n    aborting...\r\n");
		return;
	}	
	
	asm("nop");
	
	// checking for previous ownership
	if(xferBuf[14] == 0x01)
	{
		printf("\r\nTPM must be cleared before TPM_TakeOwnership command");
		return;				
	}
	
	// try to read the current EK
	if(commandHandler("readEK"))
	{
		// if EK can't be read, try to generate it
		if(commandHandler("createEKPair"))
		{
			// if ekGen fails, then abort
			printf("\r\n    can't get public Endorsement Key");
			printf("\r\n    aborting...\r\n");
			return;
		}
	}

	// check for compliance mode
	memcpy(compPubEKBuf, compPubEK, sizeof(compPubEKBuf));
	if(memcmp(compPubEKBuf, &xferBuf[38], sizeof(compPubEKBuf)))
		complianceFlag = false;
	else
		complianceFlag = true;

	// save pubEK
	memmove(workBuf0, &xferBuf[38], 256);

	// create ownerAuth for bindV20 call
	if( complianceFlag == true)
		memcpy(workBuf1, ownAuth, 20);
	else
	{
		printf("\r\n    enter owner Auth: ");
		get_user_input((char*) authBuf, sizeof(authBuf), 0, USER_STRING);
		len = strlen((char*) authBuf);
		sha1_csum( authBuf, len , workBuf1 );	
	}


	// store owner auth in EEPROM
	saveOwnerAuth(workBuf1);

	// invoke bindV20 for ownerAuth
	commandHandler( "bindV20");

	// save encrypted ownerAuth
	memmove(workBuf2, &xferBuf[14], 256);

	// create SRKAuth for bindV20 call
	if( complianceFlag == true)
		memcpy(workBuf1, SRKAuth, 20);
	else
	{
		printf("\r\n    enter SRK Auth: ");
		get_user_input((char*) authBuf, sizeof(authBuf), 0, USER_STRING);
		
	    sha1_csum( authBuf, strlen((char*) authBuf), workBuf1 );
	}

	// store SRK auth in EEPROM
	saveSRKAuth(workBuf1);

	// invoke bindV20 for SRKAuth
	commandHandler( "bindV20");

	// save encrypted SRKAuth
	memmove(workBuf3, &xferBuf[14], 256);

	// select an authSession
	currentAuthSession = 0;

	// create an authSession for this command
	if(commandHandler("OIAP"))
	{
		printf("\r\ncould not start authSession");
		printf("\r\naborting...\r\n");
		return;
	}

	// now setup xferBuf for takeOwnership

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	// copy owner Auth into proper place
	memmove(&xferBuf[16], workBuf2, 256);

	// copy SRK auth into proper place
	memmove(&xferBuf[276], workBuf3, 256);

	// copy owner auth to authSession
    getOwnerAuth(authSessions[currentAuthSession].HMACKey);

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// call input auth Handler
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	printf("\r\n    takeOwnFunc called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// call output auth Handler
	outAuthHandler(pCommand->numAuths, pCommand->numOutHandles);
}
/*****************************************************************************************************/
void _bindV20Func( TPM_Command *pCommand )
{
	// fixme!  get rid of magic numbers...
	// expects pubKey in workBuf0, authData in workBuf1

	printf("\r\n    _bindV20Func called");

	// copy pubKey
	memmove(&xferBuf[14], workBuf0, 256);

	// copy authData
	memmove(&xferBuf[274], workBuf1, 20);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

}
/*****************************************************************************************************/
void OIAPFunc( TPM_Command *pCommand )
{
    // create an OIAP session in authSessions[currentAuthSession]
    // as primarily used by meta-commands, should this be in utils.c?

	printf("\r\n    OIAPFunc called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for TPM error responses
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\ncould not start authSession");
		printf("\r\naborting...\r\n");
		return;
	}

	// copy handle
	memmove(authSessions[currentAuthSession].handle, &xferBuf[10], 4);

	// copy even nonce
	memmove(authSessions[currentAuthSession].nonceEven, &xferBuf[14], 20);

}
/*****************************************************************************************************/
void sealFunc( TPM_Command *pCommand )
{
// meta function to do perform TPM_Seal on user-supplied data

	int 		slotNum;
	uint8_t		authBuf[INBUFSIZE];
	uint8_t		*pU8;

	printf("\r\n    sealFunc sequence:");

	// input / output overlay setup
	SealIn_a	*pSealIn_a = (SealIn_a*) xferBuf;
	SealIn_b	*pSealIn_b;

	// account for any pcrInfo (none used here!)
	pSealIn_b = (SealIn_b*) (&pSealIn_a->pcrInfo + convertArrayToLong(pSealIn_a->pcrInfoSize));

   	// let the user pick a parent key if any are available
	slotNum = selectHandleSlot(workBuf0, ((void*)"\r\n\r\n    pick a sealing key (0=SRK): "), includeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	// start an OSAP session using a parent key (must be storage key!)
	currentAuthSession = 0;						// using authSession[0]

	// setup OSAP parameters
	convertIntToArray(TPM_ET_KEYHANDLE, OSAPparms.entityType);

	if(slotNum == 0)
	{
		convertLongToArray(TPM_KH_SRK, OSAPparms.entityValue);
		getSRKAuth(OSAPparms.entityAuth);
	}
	else
	{
		getLoadedKeyHandle(slotNum-1, OSAPparms.entityValue);
		getLoadedKeyAuth(slotNum-1, OSAPparms.entityAuth);
	}

	// send the command and create the authSession
	if(commandHandler("OSAP"))
	{
		printf("\r\n    could not create authSession!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	printf("\r\n    sealFunc called");

	// setup correct keyHandle
	memmove(pSealIn_a->keyHandle, OSAPparms.entityValue, sizeof(pSealIn_a->keyHandle));

	// create the blob authorization value
	printf("\r\n    enter auth value for sealed blob: ");
	get_user_input((char*) authBuf,sizeof(authBuf), 0, USER_STRING);
    sha1_csum( authBuf, strlen((char*) authBuf), pSealIn_a->encAuth );

	// calculate encAuth for sealed blob
	printf("\r\n\r\n    encAuth calculation:");
	encAuthHandler(	authSessions[currentAuthSession].nonceEven,
					authSessions[currentAuthSession].HMACKey,
					pSealIn_a->encAuth);

	// get data to seal
	printf("\r\n\r\n    enter data to seal (40 chars max): ");
	// arbitrary data size limit, could be up to OAEP_SHA1_MGF1 limit for 2048 bit key: 192 bytes
	get_user_input((char*) &pSealIn_b->inData, INBUFSIZE, 0,USER_STRING);
	//flushBS((char*) &pSealIn_b->inData);	// handle backspaces
	convertLongToArray(strlen((char*) &pSealIn_b->inData) +1, pSealIn_b->inDataSize);	// account for string terminator

	// calculate / update paramSize
	// easiest to "walk" a pointer then subtract to get size
	pU8 = &pSealIn_a->pcrInfo;
	pU8 += convertArrayToLong(pSealIn_a->pcrInfoSize);
	pU8 += sizeof(pSealIn_b->inDataSize);
	pU8 += convertArrayToLong(pSealIn_b->inDataSize);
	pU8 += AUTH1_SIZE;
	convertLongToArray(pU8 - pSealIn_a->tag, pSealIn_a->parmamSize);

	// now update numBytes for sendCommand
	numBytes = convertArrayToLong(pSealIn_a->parmamSize);

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// calculate the input HMAC
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	printf("\r\n    sealFunc called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for TPM error responses
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\ncould not get sealed data");
		printf("\r\naborting...\r\n");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
	{
		printf("\r\noutput auth validation error!\r\n");
		printf("\r\naborting!!\r\n");
		return;
	}

	// save blob in EEPROM
	do
	{
		printf("\r\nstore data blob in which cacheSlot (1-5)? ");
		get_user_input(NULL, 0,  &slotNum, USER_NUM);
		
		if((slotNum >= 1) && (	slotNum <= 5))
			break;
		else
			printf("\r\nInvalid casheSlot ");

	} while (1);

	saveBlobToEE((uint8_t) (slotNum-1));
	printf("\r\n    TPM Seal Completed Successfully!\r\n");	
	
}
/*****************************************************************************************************/
void unSealFunc( TPM_Command *pCommand )
{
	// meta function to do 2-OIAP unSeal using previously sealed user data
	// user must supply the loaded parent storage key handle and the
	// sealed blob authorization

	int 		slotNum, cacheSlot;
	uint8_t		authBuf[SZ_AUTHVAL];

	printf("\r\n    unSealFunc sequence:");

	// overlay setup
	UnSealIn	*pUnSealIn = (UnSealIn*) xferBuf;
	UnSealOut	*pUnSealOut = (UnSealOut*) xferBuf;

	// let the user pick a parent key if any are available
	slotNum = selectHandleSlot(workBuf0, ((void*)"\r\n\r\n    pick a sealing key (0=SRK): "), includeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	// create 2 OIAP sessions, one for parent key, one for blob
	currentAuthSession = 0;
	if(commandHandler("OIAP"))
	{
		printf("\r\ncould not start authSession");
		printf("\r\naborting...\r\n");
		return;
	}

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	currentAuthSession = 1;
	if(commandHandler("OIAP"))
	{
		printf("\r\ncould not start authSession");
		printf("\r\naborting...\r\n");
		return;
	}

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	currentAuthSession = 0;

	// get parent key auth value
	if(slotNum == 0)
	{
		// setup the SRK as parent
		convertLongToArray(TPM_KH_SRK, pUnSealIn->parentHandle);
	    getSRKAuth(authSessions[currentAuthSession].HMACKey);
	}
	else
	{
		// use a loaded key as parent
		getLoadedKeyHandle(slotNum-1, pUnSealIn->parentHandle);
		getLoadedKeyAuth(slotNum-1, authSessions[currentAuthSession].HMACKey);
	}

	currentAuthSession = 1;

	// get blob auth from user
	printf("\r\n    enter auth value for sealed blob: ");
	get_user_input((char*) authBuf, sizeof(authBuf), 0, USER_STRING);
    sha1_csum( authBuf, strlen((char*) authBuf), authSessions[1].HMACKey );

	// get the cacheSlot from the user
	do
	{
		printf("\r\n    unseal blob from which Slot (1-5)? ");
		get_user_input(NULL, 0,  &cacheSlot, USER_NUM);
		
		if((cacheSlot >= 1) && (	cacheSlot <= 5))
			break;
		else
			printf("\r\nInvalid casheSlot ");

	} while (1);


	// insert stored sealData
	if(blobSlotValid(cacheSlot) == false)
	{
		printf( ("\r\nslot %d does not have a valid blob!"), cacheSlot);
		
		printf("\r\naborting...\r\n");
		return;
	}
	getBlobFromEE(cacheSlot, &pUnSealIn->indata);

	// calculate the input HMAC
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	printf("\r\n    unSealFunc called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// display unsealed data if successful
	if( convertArrayToLong(pUnSealOut->returnCode) == TPM_SUCCESS ){
		sprintf(("\r\nunSealed data: %s"), (char *)(&pUnSealOut->sealedData));
	}
	else
	{
		printf("\r\naborting...\r\n");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
		printf("\r\noutput auth validation error!\r\n");
		
	printf("\r\n    TPM UnSeal Completed Successfully!\r\n");	
		
}
/*****************************************************************************************************/
void activeFunc( TPM_Command *pCommand )
{
	// meta function to enable / activate a TPM
	// fixme!  doesn't check for TPM errors

	printf("\r\n    activate/enable sequence:");

	// run the enable sequence
	if(commandHandler("physPres_present"))
	{
		printf("\r\ncould not set physical presence state");
		printf("\r\naborting...\r\n");
		return;
	}
	if(commandHandler("physEnable"))
	{
		printf("\r\naborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	
	printf("\r\n    physicalSetDeactivated_false called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);
	
	printf("\r\n    TPM enable/activate Completed Successfully!\r\n");
	printf("\r\n    you may need to reset the TPM to complete this action!!!\r\n");
}
/*****************************************************************************************************/
void disableFunc( TPM_Command *pCommand )
{
	// meta function to disable / deactivate a TPM
	printf("\r\n    disable/deactivate sequence:");

	// run the disable sequence
	if(commandHandler("physPres_present"))
	{
		printf("\r\ncould not set physical presence state");
		printf("\r\naborting...\r\n");
		return;
	}
	if(commandHandler( "physSetDeact_true"))
	{
		printf("\r\naborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	printf("\r\n    physicalDisable called");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	printf("\r\n    TPM disable/deactivate Completed Successfully!\r\n");
	printf("\r\n    you may need to reset the TPM to complete this action!!!\r\n");
}
/*****************************************************************************************************/
void createWrapFunc( TPM_Command *pCommand )
{
	// meta function to create a key
	// user must supply a loaded parent storage key
	// and authorization values for the new key
	// the key and its auth will be stored in one
	// of the cache slots for later use

	int 		slotNum, optNum;
	uint8_t		authBuf[SZ_AUTHVAL];
	uint8_t		authVal[INBUFSIZE];
	bool		validOption;

	// overlay setup
	CreateWrapKeyIn	*pCreateWrapKeyIn = (CreateWrapKeyIn*) xferBuf;

	printf("\r\n    TPM_CreateWrapKey sequence:\r\n");

	// let the user pick a parent key if any are available
	slotNum = selectHandleSlot(workBuf0, ((void*)"\r\n\r\n    pick a parent key (0=SRK): "), includeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	// start an OSAP session using a parent key (must be storage key!)
	currentAuthSession = 0;						// using authSession[0]

	// setup OSAP parameters
	convertIntToArray(TPM_ET_KEYHANDLE, OSAPparms.entityType);

	if(slotNum == 0)
	{
		convertLongToArray(TPM_KH_SRK, OSAPparms.entityValue);
		getSRKAuth(OSAPparms.entityAuth);
	}
	else
	{
		getLoadedKeyHandle(slotNum-1, OSAPparms.entityValue);
		getLoadedKeyAuth(slotNum-1, OSAPparms.entityAuth);
	}

	// send the command and create the authSession
	if(commandHandler("OSAP"))
	{
		printf("\r\ncould not start authSession");
		printf("\r\naborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	printf("\r\n    createWrapFunc called");

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// get key migration auth
	printf("\r\n    enter key migration Auth: ");
	get_user_input((char*) authVal, sizeof(authVal), 0, USER_STRING);
	//flushBS((char*) authVal);	// handle backspaces
    sha1_csum( authVal, strlen((char*) authVal), authBuf );

	// overwrite template migration auth data with new auth values
	memmove(	pCreateWrapKeyIn->dataMigrationAuth,
				authBuf,
				sizeof(pCreateWrapKeyIn->dataMigrationAuth));

	// get key usage auth
	printf("\r\n    enter key usage Auth: ");
	get_user_input((char*) authVal, sizeof(authVal), 0, USER_STRING);
	//flushBS((char*) authVal);	// handle backspaces
    sha1_csum( authVal, strlen((char*) authVal), authBuf );

	// overwrite template usage auth data with new auth values
	memmove(pCreateWrapKeyIn->dataUsageAuth, authBuf, sizeof(pCreateWrapKeyIn->dataUsageAuth));

	// calculate encAuth for usageAuth
	printf("\r\n\r\n    useageAuth calculation:");
	encAuthHandler(	authSessions[currentAuthSession].nonceEven,
					authSessions[currentAuthSession].HMACKey,
					pCreateWrapKeyIn->dataUsageAuth);

	// calculate encAuth for migrationAuth -- must use nonceOdd
	printf("\r\n\r\n    migrationAuth calculation:");
	encAuthHandler(	authSessions[currentAuthSession].nonceOdd,
					authSessions[currentAuthSession].HMACKey,
					pCreateWrapKeyIn->dataMigrationAuth);

	// overwrite template parentHandle OSAP entity value
	memmove(	pCreateWrapKeyIn->parentHandle,
				OSAPparms.entityValue,
				sizeof(pCreateWrapKeyIn->parentHandle));

	// now ask the user for the key parameters

	// key usage / type
	validOption = false;
	while( validOption == false)
	{
		printf("\r\n");
		printf("\r\n    1: storage");
		printf("\r\n    2: signing    ");
		printf("\r\n\r\n    please pick a key type: ");
		//scanf( ("%d*"), &optNum);
		get_user_input(NULL, 0,  &optNum, USER_NUM);

	switch( optNum )
		{
			case 1:
				// keyUsage
				convertIntToArray(TPM_KEY_STORAGE, pCreateWrapKeyIn->keyParms.keyUsage);
				// schemes
			    convertIntToArray(TPM_ES_RSAESOAEP_SHA1_MGF1, pCreateWrapKeyIn->keyParms.keyParms.encScheme);
			    convertIntToArray(TPM_SS_NONE, pCreateWrapKeyIn->keyParms.keyParms.sigScheme);
				validOption = true;
				break;

			case 2:
				convertIntToArray(TPM_KEY_SIGNING, pCreateWrapKeyIn->keyParms.keyUsage);	// signing
				// schemes
			    convertIntToArray(TPM_ES_NONE, pCreateWrapKeyIn->keyParms.keyParms.encScheme);
			    convertIntToArray(TPM_SS_RSASSAPKCS1v15_SHA1, pCreateWrapKeyIn->keyParms.keyParms.sigScheme);
				validOption = true;
				break;

			default:
				printf("\r\ninvalid option");
		}
	}

	// key flags
	validOption = false;
	while( validOption == false)
	{
		printf("\r\n");
		printf("\r\n    1: migratable");
		printf("\r\n    2: non-migratable");
		printf("\r\n\r\n    please pick a key option: ");
		//scanf( ("%d*"), &optNum);
		get_user_input(NULL, 0,  &optNum, USER_NUM);
		
		switch( optNum )
		{
			case 1:
				convertLongToArray(TPM_MIGRATABLE, pCreateWrapKeyIn->keyParms.keyFlags);
				validOption = true;
				break;

			case 2:
				convertLongToArray(TPM_NONMIGRATABLE, pCreateWrapKeyIn->keyParms.keyFlags);
				validOption = true;
				break;

			default:
				printf("\r\ninvalid option");
		}
	}

	// authDataUsage
	validOption = false;
	while( validOption == false)
	{
		printf("\r\n");
		printf("\r\n    1: authDataUsage = TPM_AUTH_ALWAYS");
		printf("\r\n    2: authDataUsage = TPM_AUTH_NEVER");
		printf("\r\n\r\n    please pick a key option: ");
		//scanf("%d*", &optNum);
		get_user_input(NULL, 0,  &optNum, USER_NUM);

		switch( optNum )
		{
			case 1:
				pCreateWrapKeyIn->keyParms.authDataUsage = TPM_AUTH_ALWAYS;
				validOption = true;
				break;

			case 2:
				pCreateWrapKeyIn->keyParms.authDataUsage = TPM_AUTH_NEVER;
				validOption = true;
				break;

			default:
				printf("\r\ninvalid option");
		}
	}

	// get the auth for the sealing key
	if(slotNum == 0)
	{
		convertLongToArray(TPM_KH_SRK, OSAPparms.entityValue);
		getSRKAuth(OSAPparms.entityAuth);
	}
	else
	{
		getLoadedKeyHandle(slotNum-1, OSAPparms.entityValue);
		getLoadedKeyAuth(slotNum-1, OSAPparms.entityAuth);
	}

	// calculate the input HMAC
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for success
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    error creating key!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
	{
		printf("\r\noutput auth validation error!\r\n");
		printf("\r\naborting!!\r\n");
		return;
	}

	do 
	{
		printf("\r\nstore key in which cacheSlot (1-5)? ");
		get_user_input(NULL, 0,  &slotNum, USER_NUM);	
		
		if((slotNum >= 1) && (	slotNum <= 5)) 
			break;
		else
			printf("\r\nInvalid casheSlot ");

	} while (1);
	
	// save key and keyAuth in EEPROM
	saveKeyToEE((uint8_t) (slotNum-1), authBuf);
	
	printf("\r\n    TPM Create WrapKey Completed Successfully!\r\n");
}
/*****************************************************************************************************/
void loadKeyFunc( TPM_Command *pCommand )
{
	// meta function to load a key
	// user must provide the proper loaded parent key handle
	// the key handle and auth value will be stored in a loaded
	// handle storage slot.

	// Note:  This is not necessarily good practice!  The key's
	//        auth data will be in unprotected EE.  This method
	//        should only be used if the physical and
	//        communication security of the system can be
	//        guaranteed!

	uint16_t	keySize;
	static int 		slotNum, cacheSlot;

	// overlay setup
	LoadKeyIn	*pLoadKeyIn = (LoadKeyIn*) xferBuf;
	LoadKeyOut	*pLoadKeyOut = (LoadKeyOut*) xferBuf;

	printf("\r\n    TPM_LoadKey sequence:");

	// get the cacheSlot from the user
	do
	{
		printf("\r\n\r\nload key from which cacheSlot (1-5)? ");
		get_user_input(NULL, 0,  &cacheSlot, USER_NUM);
		
		if((cacheSlot >= 1) && (	cacheSlot <= 5))
			break;
		else
			printf("\r\nInvalid casheSlot ");
	} while (1);

	// decrement to re-align
	if(cacheSlot)
	{
		cacheSlot--;
	}
	
	if(keySlotValid(cacheSlot) == false)
	{
		printf( ("\r\ncacheSlot %d does not have a valid key!"), cacheSlot);
		printf("\r\naborting...\r\n");
		return;
	}

	// start an oiap session
	if(commandHandler("OIAP"))
	{
		printf("\r\n\r\n    error creating authSession");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	// now get the key from the EEPROM slot
	if( (keySize = getKeyFromEE(cacheSlot, (uint8_t*) &pLoadKeyIn->keyParms)) == 0)
	{
		printf( ("\r\nerror reading key from cacheSlot %d!"), cacheSlot);
		
		printf("\r\naborting...\r\n");
		return;
	}

	// adjust numBytes to account for keySize
    numBytes += keySize;

	// adjust numBytes to account for authorization data
    numBytes += SZ_INAUTH;

	// update paramSize to numBytes
	convertLongToArray(numBytes, pLoadKeyIn->parmamSize);

	// select the authSession
	currentAuthSession = 0;

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// let the user pick a parent key if any are available
	slotNum = selectHandleSlot(workBuf0, (void*)("\r\n\r\n    pick a parent key (0=SRK): "), includeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	if(slotNum == 0)
	{
		// setup the SRK as parent
		convertLongToArray(TPM_KH_SRK, pLoadKeyIn->parentHandle);
	    getSRKAuth(authSessions[currentAuthSession].HMACKey);
	}
	else
	{
		// use a loaded key as parent
		getLoadedKeyHandle(slotNum-1, pLoadKeyIn->parentHandle);
		getLoadedKeyAuth(slotNum-1, authSessions[currentAuthSession].HMACKey);
	}

	// calculate input HMAC
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for successful load
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    error loading key!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
	{
		printf("\r\noutput auth validation error!\r\n");
		printf("\r\naborting!!\r\n");
		return;
	}

	// save loaded handle
	saveKeyHandle(cacheSlot, pLoadKeyOut->keyHandle);
	printf("\r\n    TPM Load Key Completed Successfully!\r\n");
}
/*****************************************************************************************************/
void forceClearFunc( TPM_Command *pCommand )
{
// meta function to forceClear the TPM

	printf("\r\n    TPM_ForceClear sequence called");

	//printf("\r\n    forceClearFunc sequence:");

	if(commandHandler("physPres_present"))
	{
		printf("\r\ncould not set physical presence state");
		printf("\r\naborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	


	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// if successful, clear the local key storage
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) == TPM_SUCCESS )
	{
		initKeyStore(); 		// generated keys in cache
		initLoadedKeyStore(); 	// keys loaded on TPM
	}

	if(commandHandler("physPres_notpresent"))
	{
		printf("\r\ncould not turn off physical presence state");
		printf("\r\naborting...\r\n");
		return;
	}

	printf("\r\n    note: TPM is now disabled / deactivated!\r\n");	
	printf("\r\n    TPM Force Clear Completed Successfully!\r\n");


}
/*****************************************************************************************************/
void flushKeyFunc( TPM_Command *pCommand )
{

	// allows user to flush keys from TPM and internal storage

	uint16_t	i, j, numLoadedKeys;
	int 		selectNum, slotNum;

	// setup command overlay
	FlushKeyIn	*pFlushKeyIn = (FlushKeyIn*) xferBuf;

	printf("\r\n    flushKeyFunc called");

   	// let the user pick a key if any are available
   	// note this code is slightly different from selectHandleSlot() (SRK not valid)
	numLoadedKeys = getKnownKeyHandles(workBuf0);
	if( numLoadedKeys != 0 )
	{
			printf("\r\n    known keyHandles:");
			for(i=0; i < numLoadedKeys; i++)
			{
				printf( ("\r\n        %d: "), (i+1) );
				
				for(j = i*SZ_HAND; j < i*SZ_HAND + SZ_HAND; j++){
					printf( ("%02X "), workBuf0[j] );
					
				}
			}

			do
			{
				printf("\r\n\r\n    pick a key to flush: ");
				get_user_input(NULL, 0,  &selectNum, USER_NUM);
					
				if((selectNum >= 1) && (	selectNum <= 5))
					break;
				else
					printf("\r\nInvalid casheSlot ");

			} while (1);
			
			/* decrement to align slot number */
			selectNum--;
			
	}
	else
	{
		printf("\r\n    no known keys!\r\n");
		printf("\r\n    aborting...\r\n");
		return;
	}




	// get the slot associated with this selection
	if( (slotNum = findKeyHandle(convertArrayToLong(&workBuf0[selectNum*SZ_HAND]))) == INVALID_HANDLE)
	{
		printf("\r\n    invalid handle number");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// insert keyHandle into command payload
	getLoadedKeyHandle(slotNum, pFlushKeyIn->handle);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for TPM error responses
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    TPM_FlushSpecific failed!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// remove key from internal storage
	flushKeyHandle(slotNum);
}
/*****************************************************************************************************/
void getPubKeyFunc( TPM_Command *pCommand )
{
	// meta function to retrieve a public key from .

	int 		slotNum;

	// xferBuf overlay setup
	GetPubKeyIn	*pGetPubKeyIn = (GetPubKeyIn*) xferBuf;

	// select the authSession
	currentAuthSession = 0;

	// start an oiap session
	if(commandHandler("OIAP"))
	{
		printf("\r\n\r\n    error creating authSession");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

   	// let the user pick a key if any are available
	slotNum = selectHandleSlot(workBuf0, ((void*)"\r\n\r\n    select a keyHandle: "), excludeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	// insert keyHandle into command payload
	if( !getLoadedKeyHandle(slotNum-1, pGetPubKeyIn->keyHandle) )
	{
		printf("\r\n\r\n    getPubKey: invalid keyHandle slot");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// retreive the key's auth
	getLoadedKeyAuth(slotNum-1, authSessions[currentAuthSession].HMACKey);

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// call input auth Handler
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	printf("\r\n    getPubKeyFunc called:");

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for successful execution
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    TPM_GetPubKey failed!");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
	{
		printf("\r\noutput auth validation error!\r\n");
		printf("\r\naborting!!\r\n");
		return;
	}
}
/*****************************************************************************************************/
void signFunc( TPM_Command *pCommand )
{
	// meta function to perform a TPM_Sign on user-supplied
	// data.  User must provide a TPM loaded signature key handle.
	// The signing key must also be present in a local cacheSlot
	// if it is desired to use verifySign to check the signature
	// since this uses the public part of the signing key
	
	int 		slotNum;

	// xferBuf overlay setup
	SignIn	*pSignIn = (SignIn*) xferBuf;

	printf("\r\n    sign sequence:");

	// select the authSession
	currentAuthSession = 0;

	// start an oiap session
	if(commandHandler("OIAP"))
	{
		printf("\r\n\r\n    error creating authSession");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	// let the user pick a parent key if any are available
	slotNum = selectHandleSlot(workBuf0, ((void*)"\r\n\r\n    pick a signing key: "), excludeSRK);
	if(slotNum == INVALID_HANDLE)
		return;

	if(slotNum == 0)
	{
		// setup the SRK as parent (note: this is illegal, left in for demo purposes)
		convertLongToArray(TPM_KH_SRK, pSignIn->keyHandle);
	    getSRKAuth(authSessions[currentAuthSession].HMACKey);
	}
	else
	{
		// use a loaded key as parent
		getLoadedKeyHandle(slotNum-1, pSignIn->keyHandle);
		getLoadedKeyAuth(slotNum-1, authSessions[currentAuthSession].HMACKey);
	}

	// get input data from user to sign
	// arbitrary data size limit, could be any size since signature with key scheme of
	// TPM_SS_RSASSAPKCS1v15_SHA1 is always performed on a SHA-1 digest (output
	// size 20 bytes)
	printf("\r\n\r\n    enter data to sign (40 chars max): ");
	get_user_input((char*) workBuf0, INBUFSIZE, 0, USER_STRING);
	//flushBS((char*) workBuf0);	// handle backspaces
    sha1_csum( workBuf0, strlen((char*) workBuf0), &pSignIn->areaToSign );

	// get a nonceOdd
	getNonceOdd(authSessions[currentAuthSession].nonceOdd, fixedNonce);

	// calculate input HMAC
	inAuthHandler(pCommand->numAuths, pCommand->numInHandles);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for successful sign
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    sign error!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// call output auth Handler
	if(outAuthHandler(pCommand->numAuths, pCommand->numOutHandles))
	{
		printf("\r\noutput auth validation error!\r\n");
		printf("\r\naborting!!\r\n");
		return;
	}

	do
	{
		printf("\r\nstore signature in which cacheSlot (1-5)? ");
		get_user_input(NULL, 0,  &slotNum, USER_NUM);
		
		if((slotNum >= 1) && (slotNum <= 5))
			break;
		else
			printf("\r\nInvalid casheSlot ");
	} while (1);

	// save signature
	saveSigToEE((slotNum-1));

	printf("\r\n    TPM Sign Completed Successfully!\r\n");
}
/*****************************************************************************************************/
void verifySignFunc( TPM_Command *pCommand )
{
	// meta function to perform a TPM_VerifySign on user-supplied
	// data.  User must provide the keyHandle of a loaded signing
	// key which was used to sign that data, as well as a cacheSlot
	// which contains the signature data.  The public portion of
	// that key will be used to verify the stored signature against
	// the user supplied data; if the data or the public key is
	// mismatched the command will fail.

	// Note:  This is an Atmel specific command provided as a
	//        convenience to TSS and application developers; the
	//        TSS is required to implement this functionality in
	//        environments where it is present.

	uint16_t	sigSize, pubKeySize;
	int cacheSlot;
	
	// xferBuf overlay setup
	VerifySigInA	*pVerifySigInA = (VerifySigInA*) xferBuf;
	VerifySigInB	*pVerifySigInB;
	GetPubKeyOut 	*pGetPubKeyOut = (GetPubKeyOut*) xferBuf;

	// retrieve the public key from a TPM loaded (signing) key
	if(commandHandler("getPubKey"))
	{
		printf("\r\n\r\n    error retrieving public key!");
		printf("\r\n    aborting...\r\n");
		return;
	}

	// the signature size is the same as the public modulus size
	sigSize = convertArrayToLong(pGetPubKeyOut->pubKey.ST_pubKey.keySize);
	pVerifySigInB = (VerifySigInB*) (&pVerifySigInA->signature + sigSize);
	pubKeySize = sizeof(GetPubKeyOut)- 10 + sigSize - 1;		// account for marker

	// move the output TPM_Pubkey structure into proper place for verifySign input
	// Note:	this will not be overwritten since the VerifySigInA template does not
	// 			include this data
	memmove(	(uint8_t*) &pVerifySigInB->pubSigKey,
				(uint8_t*) &pGetPubKeyOut->pubKey,
				pubKeySize);

	// reload numBytes for this command
	numBytes = pCommand->commandSize;

	// reload xferBuf with command template data
	memcpy(&xferBuf,pCommand->commandBytes,pCommand->commandSize);	

	// get input data from user to use with VerifySign
	// arbitrary data size limit, could be any size since signature with key scheme
	// of TPM_SS_RSASSAPKCS1v15_SHA1 is always performed on a SHA-1 digest (output
	// size 20 bytes)
	printf("\r\n\r\n    enter signature verification data (40 chars max): ");
	get_user_input((char*) workBuf0, INBUFSIZE, 0, USER_STRING);
	//flushBS((char*) workBuf0);	// handle backspaces
    sha1_csum( workBuf0, strlen((char*) workBuf0), pVerifySigInA->digest );

	// get the signature cacheSlot from the user
	do
	{
		printf("\r\n    verify sign using signature from which cacheSlot (1-5)? ");
		get_user_input(NULL, 0,  &cacheSlot, USER_NUM);
		
		if((cacheSlot >= 1) && (cacheSlot <= 5))
			break;
		else
			printf("\r\nInvalid casheSlot ");
	} while (1);
	
	
	// decrement to re-align 
	if(cacheSlot)
	{
	  cacheSlot--;
	}
	
	
	if(sigSlotValid(cacheSlot) == false)
	{
		printf( ("\r\ncacheSlot %d does not have a valid signature!"), cacheSlot);
		printf("\r\naborting...\r\n");
		return;
	}

	// now get the signature from the EEPROM slot
	if( (sigSize = getSigFromEE(cacheSlot, &pVerifySigInA->signature)) == 0)
	{
		printf( ("\r\nerror reading signature from cacheSlot %d!"), cacheSlot);
		
		printf("\r\naborting...\r\n");
		return;
	}

	printf("\r\n    verifySignFunc called:");

	// update the signature size parameter
	convertLongToArray(sigSize, pVerifySigInA->sigSize);

	// update numBytes, paramSize
	numBytes =	sizeof(VerifySigInA) -1 +
				convertArrayToLong(pVerifySigInB->pubSigKey.ST_pubKey.keySize) +
				pubKeySize;
	convertLongToArray( numBytes, pVerifySigInA->parmamSize);

	// send/receive TPM bytes
	sendCommand(getResponse, getLog);

	// check for successful signature verifcation
	if( convertArrayToLong(((TPM_return*) xferBuf)->returnCode) != TPM_SUCCESS )
	{
		printf("\r\n    error verifying signature!");
		return;
	}
	else
		printf("\r\n    signature verification complete!");
}


void get_user_input(char * str, int array_size, int *value, uint8_t type )
{
	uint8_t ch;
	uint8_t nIndex = 0;
    char tnum;
	
	do{
		
		  switch(type)
		  {
			  case USER_STRING:
		  
					scanf("%c",&ch);
			
					if (ch)
					{
						if(ch == '\r')
						{
							/* string termination */
							asm("nop");
							*str++ = '\0';
							return;
						}
						else if(nIndex < (array_size-1))
						{
							/* echo to output */
							printf("%c",ch);
							*str++ = ch;
						}
						else /*buffer overflow */
						{
							*str = '\0';
							printf("\r\n    %s\r\n",str);
							return;
						}
						nIndex++;
					}		  
		  
			  break;
		   
			  case USER_NUM:
				/* todo - redo this code,
				    make more robust */
				tnum = getc(stdin);
				*value = atoi(&tnum);
				printf("%d",*value);
				 
				 return; 

		  }

	}while(1);

}


/* error notification */
/* error notification */
/* error notification */
void error_notification(TPM_Command *pCommand)
{
	uint32_t errCode = convertArrayToLong(((TPM_return*) xferBuf)->returnCode);


	/* error notification */
	switch(pCommand->commandTPM)
	{
		
		case TPM_CMD_STARTUP_CLEAR:
			if(errCode == 0x26)
				printf("\r\nTPM_POSTINIT error.\r\nTPM_Startup_Clear command can only be executed once per POR");
		break;
		
		case TPM_CMD_PHYSPRES_PRESENT:
			if(errCode == 0x03)
				printf("\r\nTPM_BAD_PARAMETER error.\r\nPhysical Presence command can not be executed.");
		break;
		
		case TPM_CMD_CREATE_EKPAIR:
			if(errCode == 0x08)
				printf("\r\nTPM_CMD_DISABLED error.\r\nEndorsement Key already Created.");
		break;
		
		case TPM_CMD_CONT_SELFTEST:
			if(errCode == 0x26)
				printf("\r\nTPM_POSTINIT error.\r\nTPM_Startup_Clear command can only be executed once per POR");
		break;
		case TPM_CMD_TAKE_OWNERSHIP:
		case TPM_CMD_OIAP:///Taken out of code
		case TPM_CMD_OSAP:///Taken out of code
		case TPM_CMD_OSAP_ET_KH_SRK:
		case TPM_CMD_CREATE_WRAPKEY:
		case TPM_CMD_LOADKEY:
		case TPM_CMD_READKEY:
		case TPM_CMD_SEAL:
		case TPM_CMD_UNSEAL:
		case TPM_CMD_SIGN:
		case TPM_CMD_VERIFY_SIGN:
		case TPM_CMD_GET_PUB_KEY:
		case TPM_CMD_BINDV20_G:
		case TPM_CMD_GET_CAP_VERSVAL:
		case TPM_CMD_RESET:
		case TPM_CMD_FLUSHKEY:
		case TPM_CMD_FORCE_CLEAR:
		case TPM_CMD_PHYS_SET_DEACT_FALSE:
		case TPM_CMD_PHYS_DISABLE:
		case TPM_CMD_PHYS_ENABLE:
		case TPM_GETCAP_VERSION:	
		case TPM_CMD_PHY_SET_DEACT_TRUE:
		case TPM_CMD_GET_VERSION:
		case TPM_CMD_CREATE_WRAPKEY_PCR:
		case TPM_CMD_TERMINATE_HANDLE1:///Taken out of code
		case TPM_CMD_TERMINATE_HANDLE0:///Taken out of code
		case TPM_CMD_GET_SET_MEM:///Taken out of code
		case TPM_CMD_GET_CAP_PROP_OWNER:
		case TPM_CMD_OSAP_ET_KEY_SRK:
	
		
		if(errCode == 0x26)
			printf("\r\nTPM_POSTINIT error.\r\nTPM_Startup_Clear command must be first command executed.");
		
		break;
		
	}
}

void success_post_processing(TPM_Command *pCommand)
{
	/* command requiring post-processing */
	switch(pCommand->commandTPM)
	{
		
		case TPM_CMD_GET_CAP_VERSVAL:
			printf("\r\nTPM version: %02X.%02X.%02X.%02X", xferBuf[16], \
					xferBuf[17],xferBuf[18],xferBuf[19]);
		break;
		
		case TPM_CMD_STARTUP_CLEAR:
		case TPM_CMD_PHYSPRES_PRESENT:
		case TPM_CMD_CREATE_EKPAIR:
		case TPM_CMD_CONT_SELFTEST:
		case TPM_CMD_TAKE_OWNERSHIP:
		case TPM_CMD_OIAP:///Taken out of code
		case TPM_CMD_OSAP:///Taken out of code
		case TPM_CMD_OSAP_ET_KH_SRK:
		case TPM_CMD_CREATE_WRAPKEY:
		case TPM_CMD_LOADKEY:
		case TPM_CMD_READKEY:
		case TPM_CMD_SEAL:
		case TPM_CMD_UNSEAL:
		case TPM_CMD_SIGN:
		case TPM_CMD_VERIFY_SIGN:
		case TPM_CMD_GET_PUB_KEY:
		case TPM_CMD_BINDV20_G:
		case TPM_CMD_RESET:
		case TPM_CMD_FLUSHKEY:
		case TPM_CMD_FORCE_CLEAR:
		case TPM_CMD_PHYS_SET_DEACT_FALSE:
		case TPM_CMD_PHYS_DISABLE:
		case TPM_CMD_PHYS_ENABLE:
		case TPM_GETCAP_VERSION:
		case TPM_CMD_PHY_SET_DEACT_TRUE:
		case TPM_CMD_GET_VERSION:
		case TPM_CMD_CREATE_WRAPKEY_PCR:
		case TPM_CMD_TERMINATE_HANDLE1:///Taken out of code
		case TPM_CMD_TERMINATE_HANDLE0:///Taken out of code
		case TPM_CMD_GET_SET_MEM:///Taken out of code
		case TPM_CMD_GET_CAP_PROP_OWNER:
		case TPM_CMD_OSAP_ET_KEY_SRK:
		break;
		
	}	
	
}

/*****************************************************************************************************/
