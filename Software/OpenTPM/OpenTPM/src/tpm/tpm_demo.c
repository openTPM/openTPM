/*
 * tpm_demo.c
 *
 * Created: 9/6/2013 10:26:35 AM
 */ 


#include "asf.h"
#include "utils.h"
#include "tpm_demo.h"
#include "commandFuncs.h"


uint8_t menuHandler(void)
{
	uint8_t	option;
	printf("\033[2J" );	// clear VT-100 screen
	printf("\033[H"  );	// home cursor

	printf("\033[2J" );	// clear VT-100 screen
	printf("\033[H"  );	// home cursor

#ifdef TWI_INTERFACE
	printf("\r\n    TWI Demo for TPM - Version 2.0" );
	printf("\r\n   (for 3204/3205 TWI protocol only)" );
#else
	printf("\r\n    SPI Demo for TPM - Version 2.0" );
	printf("\r\n (for AT97SSC3205P SPI protocol only)" );
#endif
	
	printf("\r\n" );
	printf("\r\navailable commands:" );
	printf("\r\n\r\n" );
	printf("\r\n1  TPM_Startup(ST_CLEAR)" );
	printf("\r\n2  TPM_ContinueSelfTest" );
	printf("\r\n3  TPM_CreateEKPair" );
	printf("\r\n4  TPM_TakeOwnerShip (sequence)" );
	printf("\r\n5  TPM_CreateWrapKey (sequence)" );
	printf("\r\n6  TPM_Loadkey (sequence)" );
	printf("\r\n7  TPM_Seal (sequence)" );
	printf("\r\na  TPM_UnSeal (sequence)" );
	printf("\r\nb  TPM_Sign (sequence)" );
	printf("\r\nc  TPM_VerifySign (sequence)" );
	printf("\r\nd  TPM_GetPubKey" );
	printf("\r\n" );
	printf("\r\nt  TPM_GetCapability (versionVal)" );
	printf("\r\nu  TPM_Reset (clears authSessions)" );
	printf("\r\nv  TPM_FlushSpecifc - keyHandle" );
	printf("\r\nw  TPM_ForceClear (sequence)" );
	printf("\r\nx  enable/activate TPM (sequence)" );
	printf("\r\ny  disable/deactivate TPM (sequence)" );
	printf("\r\nz  display known keys" );
	printf("\r\n" );
	printf("\r\n" );
//	printf( "\r\nq)  quit demo                   ");

	printf("\r\n\r\nplease pick a command: ");
    scanf( " %c", &option);
	return option;
}

void doCommand(uint8_t menuOption)
{
	switch(menuOption) {
		case '1':
		commandHandler("TPM_Startup_Clear");
		break;
		case '2':
		commandHandler("contSelfTest");
		break;
		case '3':
		commandHandler("createEKPair");
		break;
		case '4':
		commandHandler("takeOwnership");
		break;
		case '5':
		commandHandler("createWrapKey");
		break;
		case '6':
		commandHandler("loadKey");
		break;
		case '7':
		commandHandler("seal");
		break;
		case 'A':
		case 'a':
		commandHandler("unSeal");
		break;
		
		case 'B':
		case 'b':
		commandHandler("sign");
		break;
		
		case 'C':
		case 'c':
		commandHandler("verifySign");
		break;
		
		case 'D':
		case 'd':
		commandHandler("getPubKey");
		break;
		
		case 'T':
		case 't':
		commandHandler("getCap_versVal");
		break;
		
		case 'U':
		case 'u':
		commandHandler("reset");
		break;
		
		case 'V':
		case 'v':
		commandHandler("flushKey");
		break;
		
		case 'W':
		case 'w':
		commandHandler("forceClear");
		break;
		
		case 'X':
		case 'x':
		commandHandler("physSetDeact_false");
		break;
		
		case 'Y':
		case 'y':
		commandHandler("physDisable");
		break;
		
		case 'Z':
		case 'z':
		showKnownKeys();
		break;
		
// 		case 'W':
// 		commandHandler("getCap_version");
// 		break;
// 		case 'X':
// 			commandHandler("getSetMem");
// 			break;
// 		case 'X':
// 			commandHandler("terminateHandle0");
// 			break;
// 		case 'Y':
// 			commandHandler("terminateHandle1");
// 			break;
		default:
		printf("\r\nInvalid option: %c", menuOption);
		scanf("%c", &menuOption);
	}
}


