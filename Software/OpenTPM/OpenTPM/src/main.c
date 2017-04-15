/**
 * \file
 *
 * \brief Empty user application template
 *
 */

/**
 * \mainpage User Application template doxygen documentation
 *
 * \par Empty user application template
 *
 * Bare minimum empty user application template
 *
 * \par Content
 *
 * -# Include the ASF header files (through asf.h)
 * -# "Insert system clock initialization code here" comment
 * -# Minimal main function that starts with a call to board_init()
 * -# "Insert application code here" comment
 *
 */

/*
 * Include header files for all drivers that have been imported from
 * Atmel Software Framework (ASF).
 */
/*
 * Support and FAQ: visit <a href="http://www.atmel.com/design-support/">Atmel Support</a>
 */
#include <asf.h>

/* #included for tpm support */
#include "tpm/tpm_demo.h"
#include "tpm/tpm_spi.h"

#include "tpm/commandFuncs.h"
#include "tpm/hashfuncs.h"

#include "tpm/utils.h"
#include "tpm/nvstorefuncs.h"

int main (void)
{
	uint8_t ch;
	bool displayMenu = true;
	
	/* Insert system clock initialization code here (sysclk_init()). */
	sysclk_init();
	board_init();

	// Initialize interrupt vector table support.
	irq_initialize_vectors();

	// Enable interrupts
	cpu_irq_enable();

	delay_init(sysclk_get_cpu_hz());
	
	stdio_usb_init();
	
	//spi_set_clock_configuration(0);
	
	while (1) {
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
	}

	/* Insert application code here, after the board has been initialized. */
}
