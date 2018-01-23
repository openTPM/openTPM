#include <stdio.h>
#include <avr/io.h>
#include <avr/pgmspace.h>

#include "globals.h"

/* Define Baud and Xtal frequency below
   (or use the CDEFS macro in makefile) */

#ifndef FOSC
	#define FOSC F_CPU
#endif

#ifndef BAUD
	#define BAUD 19200UL
#endif

#if defined (__AVR_ATmega128__)
	#define UBRRH UBRR0H
	#define UBRRL UBRR0L
	#define UCSRA UCSR0A
	#define UCSRB UCSR0B
	#define UDR UDR0
#endif

/* Sends a single char over the UART */
int UART_putchar (char c, FILE *stream)
{
	loop_until_bit_is_set (UCSRA,UDRE);	// Wait until the send register is empty

	UDR = c;							// Send char to send register
	return 0;
}

/* Holds program execution until a char is received */
int UART_getchar (FILE *stream)
{
	unsigned char c;

	loop_until_bit_is_set (UCSRA,RXC);	// Wait until a char is received

	c = UDR;

	/* convert MS-DOS CR/LF */
	if(c == '\r')
		c = '\n';

	/* This next line echo's the char, comment out if not needed */
//	UART_putchar (c, stream);

	return c;
}

void UART_init (void)
{
	/* initialize the UART */

	UBRRH = 0x00;
	UBRRL = FOSC / (16 * BAUD) - 1;		// BAUD BPS
	UCSRB = (1<<TXEN)|(1<<RXEN);		// 8 Databits

	if( fdevopen(UART_putchar, UART_getchar) == NULL )
		printf_P_flush(PSTR("\r\ncouldn't open IO stream!\r\n"));
}
