#ifndef CMDFUNCS_H
#define CMDFUNCS_H
#include "nvStoreFuncs.h"
#include "commandStructs.h"

// typedefs
#define 	USER_STRING  ((uint8_t)0)
#define		USER_NUM	((uint8_t)1)


// command overlays

typedef struct tdCreateWrapKeyIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		parentHandle[4];
	uint8_t		dataUsageAuth[20];
	uint8_t		dataMigrationAuth[20];
	keyFixed	keyParms;
	uint8_t		varKey;				// place holder, may be TPM_KEY or TPM_KEY12
} CreateWrapKeyIn;

typedef struct tdLoadKeyIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		parentHandle[4];
	keyFixed	keyParms;
	uint8_t		varKey;					// place holder, may be TPM_KEY or TPM_KEY12
} LoadKeyIn;

typedef struct tdLoadKeyOut
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		returnCode[4];
	uint8_t		keyHandle[4];
} LoadKeyOut;

// defined as split structure to handle variable length/optional members
typedef struct tdSealIn_a
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		keyHandle[4];
	uint8_t		encAuth[20];
	uint8_t		pcrInfoSize[4];
	uint8_t		pcrInfo;				// marker, does not exist if pcrInfoSize == 0
} SealIn_a;

// this comes after pcrInfo (if it exists)
typedef struct tdSealIn_b
{
	uint8_t		inDataSize[4];
	uint8_t		inData;
} SealIn_b;


typedef struct tdUnSealIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		parentHandle[4];
	uint8_t		indata;					// place holder, may be TPM_STORED_DATA or TPM_STORED_DATA12
} UnSealIn;

typedef struct tdUnSealOut
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		returnCode[4];
	uint8_t		sealedDataSize[4];
	uint8_t		sealedData;				// place holder, size is sealedDataSize
} UnSealOut;

typedef struct tdFlushKeyIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		handle[4];
	uint8_t		resourceType[4];
} FlushKeyIn;

typedef struct tdSignIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		keyHandle[4];
	uint8_t		areaToSignSize[4];
	uint8_t		areaToSign;					// place holder, is areaToSignSize bytes
} SignIn;

typedef struct tdSignOut
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		returnCode[4];
	uint8_t		sigSize[4];
	uint8_t		sig;						// place holder, is sigSize bytes
} SignOut;

typedef struct tdGetPubKeyIn
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		keyHandle[4];
} GetPubKeyIn;

typedef struct tdGetPubKeyOut
{
	uint8_t			tag[2];
	uint8_t			parmamSize[4];
	uint8_t			returnCode[4];
	TPM_Pubkey		pubKey;
} GetPubKeyOut;

typedef struct tdVerifySigInA
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		ordinal[4];
	uint8_t		digestSize[4];
	uint8_t		digest[20];
	uint8_t		sigSize[4];
	uint8_t		signature;					// marker, is sigSize bytes
} VerifySigInA;

typedef struct tdVerifySigInB
{
	TPM_Pubkey	pubSigKey;
} VerifySigInB;

typedef struct tdVerifySigOut
{
	uint8_t		tag[2];
	uint8_t		parmamSize[4];
	uint8_t		returnCode[4];
	uint8_t		sigSize[4];
	uint8_t		sig;						// place holder, is sigSize bytes
} VerifySigOut;



// command handlers
bool commandHandler (const char *str);
//bool commandHandler (tpm_command commandName);

void Testfcn (char *);
void dummyFunc(   TPM_Command *pCommand );
void genericFunc(  TPM_Command *pCommand );
void takeOwnFunc(  TPM_Command *pCommand );
void _bindV20Func(  TPM_Command *pCommand );
void OIAPFunc(  TPM_Command *pCommand );
//void OSAPFunc(  TPM_Command *pCommand ); 	// OSAPHandler does OSAP (in utils.c)
void sealFunc(  TPM_Command *pCommand );
void unSealFunc(  TPM_Command *pCommand );
void signFunc(  TPM_Command *pCommand );
void VerifySignFunc(  TPM_Command *pCommand );
void activeFunc(  TPM_Command *pCommand );
void disableFunc(  TPM_Command *pCommand );
void createWrapFunc(  TPM_Command *pCommand );
void forceClearFunc(  TPM_Command *pCommand );
void loadKeyFunc( TPM_Command *pCommand );
void flushKeyFunc( TPM_Command *pCommand );
void getPubKeyFunc( TPM_Command *pCommand );
void verifySignFunc( TPM_Command *pCommand );
void init_xferbuf(void);
void get_user_input(char * str, int array_size,int *value, uint8_t type);
void error_notification(TPM_Command *pCommand );
void success_post_processing(TPM_Command *pCommand);
#endif

