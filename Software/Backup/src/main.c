/**
 * \file
 *
 * \brief USB Standard I/O (stdio) Example
 *
 * Copyright (c) 2011 - 2012 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

/**
 * \mainpage
 *
 * \section intro Introduction
 * This example demonstrates how to configure a C-library Standard
 * I/O interface to the ASF common USB Device CDC service. The initialization
 * routines, along with board and clock configuration constants, illustrate how
 * to perform serial I/O via a Communication Device Class (CDC) device protocol
 *
 * \section files Main Files
 * - stdio_usb_example.c: the example application.
 * - conf_board.h: board configuration
 * - conf_clock.h: board configuration
 * - stdio_usb.h: Common USB CDC Standard I/O Implementation
 * - read.c : System implementation function used by standard library
 * - write.c : System implementation function used by standard library
 *
 * \section example_description Description of the example
 *   - Send message on USB CDC device to a Virtual Com Port.
 *   - Performs echo of any received character
 *
 * \section contactinfo Contact Information
 * For further information, visit
 * <A href="http://www.atmel.com/avr">Atmel AVR</A>.\n
 */

#include <asf.h>
#include <board.h>
#include <sysclk.h>
#include <stdio_usb.h>
#include "conf_board.h"
#include "physical.h"
#include "gpio.h"
#include "delay.h"

/* #included for tpm support */
#include "tpm_demo.h"
#include "tpm_spi.h"

/* physical layer support */
#include "spi.h"
#include "spi_master.h"
#include "commandFuncs.h"
#include "hashfuncs.h"
//#include "sha1_test.h"
#include "utils.h"
#include "nvstorefuncs.h"


#ifdef MFG_SUPPORT

	#include "parserAscii.h"
	#define KIT_EOP	((uint8_t)'\n')
	extern uint8_t pucUsbRxBuffer[USB_BUFFER_SIZE_RX];
	
#endif

#define STRING_EOL    "\r"
#define STRING_HEADER "-- Flash Program Example --\r\n" \
"-- "BOARD_NAME" --\r\n" \
"-- Compiled: "__DATE__" "__TIME__" --"STRING_EOL

typedef unsigned long UL;

		
/**
 * \brief main function
 */
int main (void)
{
 	uint8_t ch;
	bool displayMenu = true;


#ifdef MFG_SUPPORT
	static uint8_t i =0;
	static char localRxBuf[30];
	uint16_t tx_size;
	uint8_t localRxBuffer [300];
	uint8_t localTxBuffer [300];
	uint8_t volatile vCollateUsbPacket = 0;
	uint16_t byteRxed = 0;
	uint8_t *pRx = &localRxBuffer[0];
	uint8_t *pTx = &localTxBuffer[0];
#endif	
	

	
	/* Initialize basic board support features.
	 * - Initialize system clock sources according to device-specific
	 *   configuration parameters supplied in a conf_clock.h file.
	 * - Set up GPIO and board-specific features using additional configuration
	 *   parameters, if any, specified in a conf_board.h file.
	 */
	sysclk_init();
	board_init();

	// Initialize interrupt vector table support.
	irq_initialize_vectors();

	// Enable interrupts
	cpu_irq_enable();

	delay_init(sysclk_get_cpu_hz());

	//nvm_unit_test();

	
	
	/* Call a local utility routine to initialize C-Library Standard I/O over
	 * a USB CDC protocol. Tunable parameters in a conf_usb.h file must be
	 * supplied to configure the USB device correctly.
	 */
	stdio_usb_init();

	#ifdef TWI_INTERFACE

		/* Enable the peripheral clock for TWI */
		pmc_enable_periph_clk(TPM_TWI_MODULE_ID);
		twi_init();

	#else // SPI
		spi_set_clock_configuration(0);
	#endif

 	while (1) {
	

 		#ifdef MFG_SUPPORT
		 
// 		 	ch = menuHandler();
// 		 			
// 		 			
// 		 	if (ch)
// 		 	{
// 			 	/* echo to output */
// 			 	printf("%c",ch);
// 
// 			 	if(ch == '\033')
// 			 	{
// 				 	ch = menuHandler();
// 			 	}
// 
// 			 	/* testing SPI hardware interface */
// 			 	doCommand(ch);
// 		 	}

		 	scanf("%c",&ch); 

// 		 	if (ch)
// 		 	{
// 				 localRxBuf[i++]=  ch;
// 				 if(i == 10)
// 					asm("nop");
// 		 	}

			if(byteRxed < sizeof(pucUsbRxBuffer))
			{
				pucUsbRxBuffer[byteRxed++] = ch;						
				if(ch == KIT_EOP)
				{
					/* correlate packet */
					if (CollateUsbPacket(byteRxed, &pRx))
					{
						pRx = ProcessUsbPacket(&tx_size);
						asm("nop");
						//print_usb(tx_size, tx_buffer);
						byteRxed = 0;
					}
					else /* error occurred */
						byteRxed =0;
				}				
			}
			else /* error occurred */
				byteRxed = 0;
 
 		#else
			/* mimics the old kit, menu driven */
			
		    /* display menu 1st time through
			 * on any character pressed
			 */
			if(displayMenu)
			{
				/* retrieve user input */
				//scanf( " %c", &ch);
				ch = getc(stdin);
				if(ch)
				{
					displayMenu = false;
					/* display menu and wait for
					 * user selection 
					 */
					ch = menuHandler();
					
					/* echo, provide user feedback */
					printf("%c",ch);
					
					/* execute command */
					doCommand(ch);					
				}				
			}
			else
			{
				ch = menuHandler();		
				if (ch)
				{
					/* echo, provide user feedback */
					printf("%c",ch);
					/* execute command */
					doCommand(ch);
				}

			}

		#endif	
	}
}

