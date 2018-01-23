#include <avr/io.h>
#include <avr/pgmspace.h>
#include <stdio.h>

#include "UART.h"

int main(void) 
{
	unsigned char s [40];

	// First init UART
	UART_init ();

	for (;;) 
	{
		/* Same function as printf() but the format string resides in flash */
		printf_P_flush (PSTR ("Enter a line of text\r\n"));

//		/* Read input from UART */
//		scanf ("%s",s);

		/* Read line of input from UART */
		gets (s);

		/* Printback text */
		printf_P_flush (PSTR ("\r\nYou entered '%s'\r\n"),s);
	}
}
