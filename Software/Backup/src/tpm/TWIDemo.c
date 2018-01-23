#include <stdio.h>
#include <string.h>
//#include <avr/pgmspace.h> kmj

// USB library functions
//#include "conf_usb.h" 

// start kmj
//#include "config.h"
//#include "cdc_task.h" 
//#include "lib_mcu\usb\usb_drv.h"
//#include "usb_descriptors.h"
//#include "modules\usb\device_chap9\usb_standard_request.h"
//#include "usb_specific_request.h"
//#include "lib_mcu/uart/uart_lib.h"
//#include "uart_usb_lib.h"
// end kmj

// TPMDemo headers
#include "commandStructs.h"
#include "commandFuncs.h"
#include "UART.h"
#include "TWIFuncs.h"
#include "nvStoreFuncs.h"
#include "utils.h"

// local protos
uint8_t menuHandler(void);
void doCommand(uint8_t menuOption);

void TPM_task_init(void)
{
   uart_init();
   Leds_init();
   Joy_init();
   Hwb_button_init();
#ifdef AVRGCC
// 	fdevopen(	(int(*)(char, FILE *))	uart_usb_putchar,	//for printf redirection
//				(int(*)(FILE *))		uart_usb_getchar );
	fdevopen(uart_usb_putchar, uart_usb_getchar);
#endif

	// init TWI hw
	twi_init();

	// generate a TPM reset
	resetTPM();
}

void TPM_task(void)
{
	uint8_t	menuOption;
	static bool demoStarted = false;
// 
// 	if(Is_device_enumerated())			// Enumeration processs OK ?
// 	{
// 		if(demoStarted == false)
// 		{
// 			if (!uart_usb_test_hit())   // Something received from the USB ?
// 				return;
// 		}
// 
// 		demoStarted = true;
// 		menuOption = menuHandler();
//		if(menuOption != 'q')
			doCommand(menuOption);
//		else
//		{
//			printf_P_flush( PSTR("\r\nterminating demo...\r\n\r\n") );
//		}
//	}
}

uint8_t menuHandler(void)
{
	uint8_t	option;

	puts_P( PSTR("\033[2J") );	// clear VT-100 screen
	puts_P( PSTR("\033[H" ) );	// home cursor

	printf_P_flush( PSTR("\r\n    TWI Demo for TPM - Version 1.3") );
	printf_P_flush( PSTR("\r\n     (for 3204 TWI protocol only)") );
	printf_P_flush( PSTR("\r\n") );
	printf_P_flush( PSTR("\r\navailable commands:") );
	printf_P_flush( PSTR("\r\n\r\n") );
	printf_P_flush( PSTR("\r\n1)  TPM_Startup(ST_CLEAR)") );
	printf_P_flush( PSTR("\r\n2)  TPM_ContinueSelfTest") );
	printf_P_flush( PSTR("\r\n3)  TPM_CreateEKPair") );
	printf_P_flush( PSTR("\r\n4)  TPM_TakeOwnerShip (sequence)") );
	printf_P_flush( PSTR("\r\n5)  TPM_OIAP") );
	printf_P_flush( PSTR("\r\n6)  TPM_OSAP(ET_Keyhandle - SRK)") );
	printf_P_flush( PSTR("\r\n7)  TPM_CreateWrapKey") );
//	printf_P_flush( PSTR("\r\n8)  TPM_CreateWrapKey_PCR") );
	printf_P_flush( PSTR("\r\n8)  TPM_Loadkey") );
	printf_P_flush( PSTR("\r\n9)  TPM_Seal (sequence)") );
	printf_P_flush( PSTR("\r\na)  TPM_UnSeal (sequence)") );
	printf_P_flush( PSTR("\r\nb)  TPM_Sign (sequence)") );
	printf_P_flush( PSTR("\r\nc)  TPM_VerifySign") );
	printf_P_flush( PSTR("\r\nd)  TPM_GetPubKey") );
	printf_P_flush( PSTR("\r\ne)  TPM_BindV20") );
	printf_P_flush( PSTR("\r\n") );
	printf_P_flush( PSTR("\r\nt)  getCapability_versionVal") );
	printf_P_flush( PSTR("\r\nu)  TPM_Reset (clears authSessions)") );
	printf_P_flush( PSTR("\r\nv)  TPM_FlushSpecifc - keyHandle") );
	printf_P_flush( PSTR("\r\nw)  TPM_ForceClear (sequence)") );
	printf_P_flush( PSTR("\r\nx)  enable/activate TPM (sequence)") );
	printf_P_flush( PSTR("\r\ny)  disable/deactivate TPM (sequence)") );
	printf_P_flush( PSTR("\r\nz)  display known keys") );
	printf_P_flush( PSTR("\r\n") );
	printf_P_flush( PSTR("\r\np)  probe TPM presence") );
//	printf_P_flush( PSTR("\r\nW)  getCapability_version") );
//	printf_P_flush( PSTR("\r\nX)  getSetMem_keyInfo[0]") );
//	printf_P_flush( PSTR("\r\nX)  terminateHandle0") );
//	printf_P_flush( PSTR("\r\nY)  terminateHandle1") );
	printf_P_flush( PSTR("\r\n") );
//	printf_P_flush( PSTR("\r\nq)  quit demo                   ") );

	printf_P_flush( PSTR("\r\n\r\nplease pick a command: "));
	scanf_P( PSTR(" %c"), &option);

	return option;
}

void doCommand(uint8_t menuOption)
{
	switch(menuOption) {
		case '1':
			commandHandler("startupClear");
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
			commandHandler("OIAP");
			break;
		case '6':
			commandHandler("OSAP_ET_KH_SRK");
			break;
		case '7':
			commandHandler("createWrapKey");
			break;
//		case '8':
//			commandHandler("createWrapKey_PCR");
//			break;
		case '8':
			commandHandler("loadKey");
			break;
		case '9':
			commandHandler("seal");
			break;
		case 'a':
			commandHandler("unSeal");
			break;
		case 'b':
			commandHandler("sign");
			break;
		case 'c':
			commandHandler("verifySign");
			break;
		case 'd':
			commandHandler("getPubKey");
			break;
		case 'e':
			commandHandler("bindV20_g");
			break;
		case 'p':
			probeTPM(0x52, sendStopBit);
			break;
		case 't':
			commandHandler("getCap_versVal");
			break;
		case 'u':
			commandHandler("reset");
			break;
		case 'v':
			commandHandler("flushKey");
			break;
		case 'w':
			commandHandler("forceClear");
			break;
		case 'x':
			commandHandler("physSetDeact_false");
			break;
		case 'y':
			commandHandler("physDisable");
			break;
		case 'z':
			showKnownKeys();
			break;
		case 'W':
			commandHandler("getCap_version");
			break;
//		case 'X':
//			commandHandler("getSetMem");
//			break;
//		case 'X':
//			commandHandler("terminateHandle0");
//			break;
//		case 'Y':
//			commandHandler("terminateHandle1");
//			break;
		default:
			printf_P_flush( PSTR("\r\nInvalid option: %c"), menuOption);
			scanf_P( PSTR("%c"), &menuOption);
	}
}
