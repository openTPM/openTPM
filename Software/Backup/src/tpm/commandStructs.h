#ifndef CMDSTRUCT_H
#define CMDSTRUCT_H

#include <asf.h>
// #defines
// new GCC complains when PGM_P used with unsigned chars...
//#define const uint8_t*   const prog_uint8_t *

// enums
typedef enum { AUTH0, AUTH1, AUTH2 } authNum;
typedef enum { HAND0, HAND1, HAND2 } handleNum;


typedef enum{
	TPM_CMD_STARTUP_CLEAR,
	TPM_CMD_CONT_SELFTEST,
	TPM_CMD_CREATE_EKPAIR,
	TPM_CMD_TAKE_OWNERSHIP,
	TPM_CMD_OIAP,
	TPM_CMD_OSAP,
	TPM_CMD_OSAP_ET_KH_SRK,
	TPM_CMD_OSAP_ET_KEY_SRK,
	TPM_CMD_CREATE_WRAPKEY,
	TPM_CMD_LOADKEY,
	TPM_CMD_READKEY,
	TPM_CMD_SEAL,
	TPM_CMD_UNSEAL,
	TPM_CMD_SIGN,
	TPM_CMD_VERIFY_SIGN,
	TPM_CMD_GET_PUB_KEY,
	TPM_CMD_BINDV20_G,
	TPM_CMD_GET_CAP_VERSVAL,
	TPM_CMD_RESET,
	TPM_CMD_FLUSHKEY,
	TPM_CMD_FORCE_CLEAR,
	TPM_CMD_PHYS_SET_DEACT_FALSE,
	TPM_CMD_PHYS_DISABLE,
	TPM_CMD_PHYS_ENABLE,
	TPM_GETCAP_VERSION,
	TPM_CMD_PHYSPRES_PRESENT,
	TPM_CMD_PHY_SET_DEACT_TRUE,
	TPM_CMD_GET_VERSION,
	TPM_CMD_CREATE_WRAPKEY_PCR,
	TPM_CMD_TERMINATE_HANDLE1,
	TPM_CMD_TERMINATE_HANDLE0,
	TPM_CMD_GET_SET_MEM,
	TPM_CMD_GET_CAP_PROP_OWNER,
	TPM_CMD_PHYSPRES_NOTPRESENT
}  tpmCommand;
 



// typedefs





// command structure
typedef struct tdTPM_Command
{
	uint8_t*	commandName;
	uint8_t*	commandBytes;
	uint16_t	commandSize;
	tpmCommand	commandTPM;

	authNum		numAuths;
	handleNum	numInHandles;
	handleNum	numOutHandles;
	
}	TPM_Command;



/* command function pointer */
//typedef void (*funcPtr)(void *);
typedef void (*funcPtr)(TPM_Command *pCommand);


// command structure
typedef struct tdTPM_FuncPtr
{
	uint8_t*	commandName;
	funcPtr 	commandFunc;
}	TPM_FuncPtr;



TPM_Command *findCommand(const char *commandName);
//TPM_Command *loadCommand(tpm_command commandName);
TPM_FuncPtr *findFuncPtr(const char *commandName);
void printCommand(char *commandName);
void listCommands(void);

// defines

#define CMDTABLESIZE (sizeof(commandTable))
#define NUMCOMMANDS (sizeof(commandTable) / sizeof(TPM_Command))

// externs
extern TPM_Command commandTable[];
extern TPM_FuncPtr FuncPtrTable[];
extern uint16_t numCommands;
uint16_t commandTableSize;

extern unsigned char ownAuth[];
extern unsigned char SRKAuth[];
extern unsigned char nonceC[];
extern unsigned char compPubEK[];

#endif
