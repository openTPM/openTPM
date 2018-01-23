#include <stdio.h>
#include <string.h>
#include <avr/pgmspace.h>
#include <avr/power.h>
#include <avr/interrupt.h>
#include <util/twi.h>		/* Note [1] */

// USB library functions
//#include "config.h"
//#include "conf_usb.h"
//#include "cdc_task.h"
//#include "lib_mcu\usb\usb_drv.h"
//#include "usb_descriptors.h"
//#include "modules\usb\device_chap9\usb_standard_request.h"
//#include "usb_specific_request.h"
//#include "lib_mcu/uart/uart_lib.h"
//#include "uart_usb_lib.h"

#include "commandStructs.h"
#include "authHandler.h"
#include "globals.h"
#include "UART.h"
#include "TWIFuncs.h"
#include "utils.h"

// local #defines

// number of polling attempts to get first ACK
#define POLL_NUM 100

// turn off logging startBit bit polling attempts
//#define NO_STARTBIT_LOG

// enable 2 start bit (3201/3203) support
// #define TWO_START_BITS

// macro: wait for the TWI hardware to complete an action
#define TWIwait()  while ((TWCR & _BV(TWINT)) == 0) ;  twst = TW_STATUS;

// define an empty interrupt vector (polling used)
EMPTY_INTERRUPT(TWI_vect);
//-----------------------------------------------------------------------------
//ISR(TWI_vect)
//{
//
//}
//-----------------------------------------------------------------------------

// global var to hold transient TWSR value
volatile uint8_t	twst;

	/*********************************
	 * AVR specific TWI support code *
	 *********************************/

//-----------------------------------------------------------------------------
void twi_init(void)
{
// setup default TWI port pin states
#if defined (__AVR_ATmega128__)
	DDRD=0x00;			// all inputs (overriden when TWEN enabled)
	PORTD=0x03;			// SCL, SDA = internal pullups
#elif defined (__AVR_AT90USB1287__)
	power_twi_enable();	// enable PRTWI: Power Reduction TWI
	DDRD=0x00;			// all inputs (overriden when TWEN enabled)
	PORTD=0x03;			// SCL, SDA = internal pullups
#elif defined(__AVR_ATmega16__)
	DDRC=0x00;			// all inputs (overriden when TWEN enabled)
	PORTC=0x03;			// SCL, SDA = internal pullups
#else
	#error "This demo only supports ATMega128, AT90USB1287 and ATMega16"
#endif

	// Set the bit rate register according to datasheet formula
	// SCL frequency  = CPU Clock frequency / 16 + 2(TWBR)·4^TWPS

	TWSR = 0x00;		// bits 0, 1 = TWI prescaler (not used)
	TWBR = (F_CPU / SCLFREQ - 16 ) / 2;
}
//-----------------------------------------------------------------------------
void twi_error(uint8_t errorval)
{
	printf_P_flush( PSTR("twi_error: %d "), errorval);
//	PORTB=~errorval;
}
//-----------------------------------------------------------------------------
inline void startBit(void)
{
	TWCR = _BV(TWINT) | _BV(TWSTA) | _BV(TWEN); /* send startBit condition */
	TWIwait();
	if
	(
		(twst != MT_START) && 				// any of the legal START conditions
		(twst != MR_START) &&
		(twst != MT_REPEAT_START) &&
		(twst != MR_REPEAT_START)
	)
		twi_error(1);
}
//-----------------------------------------------------------------------------
void stopBit(void)
{
	TWCR = _BV(TWINT) | _BV(TWSTO) | _BV(TWEN); /* send stopBit condition */
}
//-----------------------------------------------------------------------------
inline uint8_t start_write(void)
{

	startBit();
	TWDR=0x52;		// read_ACK/write = WRITE
	TWCR = _BV(TWINT) | _BV(TWEN); 				/* clear interrupt to start transmission */
	TWIwait();
	if(twst != MT_SLA_ACK_W)
		twi_error(2);
	return twst;
}
//-----------------------------------------------------------------------------
inline uint8_t start_read(void)
{
		startBit();
		TWDR=0x53;		//	read_ACK/write = READ
		TWCR=(1<<TWINT)|(1<<TWEN);
		TWIwait();
		if(twst != MR_SLA_ACK_R)
			twi_error(5);
		return twst;
}
//-----------------------------------------------------------------------------
inline uint8_t start_bogus(uint8_t devAdd)
{
		startBit();
		TWDR=devAdd;
		TWCR=(1<<TWINT)|(1<<TWEN);
		TWIwait();
		if( (twst == MR_SLA_ACK_R) || (twst == MR_SLA_ACK_R) )
			twi_error(7);
		return twst;
}
//-----------------------------------------------------------------------------
inline uint8_t pollTPM(void)
{
		startBit();
		TWDR=0x53;							//	read/write = READ
		TWCR = _BV(TWINT) | _BV(TWEN); 		// clear interrupt to start transmission */
		TWIwait();
		return twst;
}
//-----------------------------------------------------------------------------
inline uint8_t read_ACK(void)
{
		uint8_t data;

//		TWIwait();											// Wait for hardware to receive data
		TWCR = _BV(TWINT) | _BV(TWEN) | _BV(TWEA);	 		// ACK
		TWIwait();
		data=TWDR;
		if(twst != MR_DATA_ACK)
			twi_error(6);
		return data;
}
//-----------------------------------------------------------------------------
inline uint8_t read_NAK(void)
{
		uint8_t data;

//		TWIwait();											// Wait for hardware to receive data
		TWCR = _BV(TWINT) | _BV(TWEN);	 					// NACK
		TWIwait();
		data=TWDR;
		if(twst != MR_DATA_NAK)
			twi_error(7);
		return data;
}
//-----------------------------------------------------------------------------
/*
#define write(data) \
	TWDR=data; \
	TWCR = _BV(TWINT) | _BV(TWEN); \
	TWIwait();
*/
//-----------------------------------------------------------------------------
inline uint8_t write(uint8_t data)
{
	TWDR=data;
	TWCR = _BV(TWINT) | _BV(TWEN);							// ACK
	TWIwait();
	if(twst != MT_DATA_ACK)
	{
		twi_error(3);
		return 1;
	}
	return 0;
}
//-----------------------------------------------------------------------------
void dumpXferBuf(void)
{
	uint16_t	i;

	for(i=0; i < numBytes; i++)
	{
		if(!(i % 16))
		{
			printf_P_flush( PSTR("\r\n"));
		}
		printf_P_flush( PSTR("%02X "), xferBuf[i] );
	}
	printf_P_flush( PSTR("\r\n"));
}
//-----------------------------------------------------------------------------
void logStartTries(uint8_t numTries)
{
	printf_P_flush( PSTR("%d tries\r\n"), numTries);
}
//-----------------------------------------------------------------------------
void convertHexToAsciiString( uint8_t hexData, char *ptrHexString )
{
	ptrHexString[0] = (hexData&0xF0)>>4;
	ptrHexString[0] += (ptrHexString[0] < 0x0A) ? 0x30 : 0x37;

	ptrHexString[1] = (hexData&0x0F);
	ptrHexString[1] += (ptrHexString[1] < 0x0A) ? 0x30 : 0x37;
}
//-----------------------------------------------------------------------------
void getcommand(void)
{
//	uint16_t i;
//
//	numBytes=0;
//	// Bytes [4] and [5] have the size data.
//	for(i=0; i<6; i++)
//		xferBuf[i] = usart_rx();
//
//	// Extract the size.
//	numBytes = xferBuf[4];
//	numBytes = numBytes<<8;
//	numBytes |= xferBuf[5];
//
//	// Get the remaining data.
//	for(i=6; i<numBytes; i++)
//		xferBuf[i] = usart_rx();
}
//-----------------------------------------------------------------------------
void probeTPM(	uint8_t slaveAdd,
				stopBitAction stopBitOption)
{
	uint8_t		slaveACKstat;
	uint16_t	i;

   // try to get an ACK from the TPM
	startBit();
	TWDR = slaveAdd;
	TWCR = _BV(TWINT) | _BV(TWEN);	// clear interrupt to start transmission
	TWIwait();

	slaveACKstat = twst;

	if(stopBitOption == sendStopBit)
	{
//		printf_P_flush( PSTR("\r\nsending stop bit") );
		TWCR = _BV(TWINT) | _BV(TWSTO) | _BV(TWEN); 	/* send stopbit condition */
//		TWIwait();
		printf_P_flush( PSTR("\r\n\r\n    TWI STATUS: %02X"), twst );
		printf_P_flush( PSTR("\r\n    TPM ACK detected") );
	}

	if( (slaveACKstat != MT_SLA_ACK_W) && (slaveACKstat != MT_REPEAT_START) &&
		(slaveACKstat != MR_SLA_ACK_R) && (slaveACKstat != MR_REPEAT_START) )
			printf_P_flush( PSTR("\r\nTPM did not ACK") );

	printf_P_flush( PSTR("\r\n\r\npress any key to continue...") );
	scanf_P( PSTR("%c"), &i);

}
//-----------------------------------------------------------------------------
void sendCommand(	responseAction 	wantResponse,
					logAction 		wantLog)
{
	uint16_t 	i;
	uint8_t		data;

	union {
		uint8_t		bytes[2];
		uint16_t	size;
	} paramSize;

	// show what we're sending
	if(wantLog == getLog)
	{
		printf_P_flush( PSTR("\r\nto TPM:") );
		dumpXferBuf();
	}

   // get the TPM's attention
	i = 0;
	do{
		data=start_write();								// send startBit, slave address/write
		i++;
	} while((data != MT_SLA_ACK_W) && (i < POLL_NUM));	// give POLL_NUM tries...

#ifndef NO_STARTBIT_LOG
	if(i > 1)
	{
		printf_P_flush( PSTR("\r\nfirst write startBit took ") );
		logStartTries(i);
		if(i == POLL_NUM)
		{
			printf_P_flush( PSTR("aborting (xmit ACK 1)\r\n") );
			return;
		}
	}
#endif

#ifdef TWO_START_BITS
	//send first 10 bytes
	for(i=0; i<10; i++)
	{
		if(write(xferBuf[i]))
		{
			printf_P_flush( PSTR("write error\r\n") );
		}
	}

	if(numBytes > 10)
	{
		// get the TPM's attention
		i = 0;
		do{
			data=start_write();									// send startBit, slave address/write
			i++;
		} while((data != MT_SLA_ACK_W) && (i < POLL_NUM));		// give POLL_NUM tries...

	#ifndef NO_STARTBIT_LOG
		if(i > 1)
		{
			printf_P_flush( PSTR("second write startBit took ") );
			logStartTries(i);
			if(i == POLL_NUM)
			{
				printf_P_flush( PSTR("aborting (xmit ACK 2)\r\n") );
				return;
			}
		}
	#endif
#endif

		//send any remaining bytes
#ifdef TWO_START_BITS
		for(i=10; i<numBytes; i++)
#else
		for(i=0; i<numBytes; i++)
#endif
		{
//			write(xferBuf[i]);			// macro call
			if(write(xferBuf[i]))
			{
				printf_P_flush( PSTR("write error\r\n") );
			}
		}
#ifdef TWO_START_BITS
	}
#endif

	if(wantResponse == getResponse)
	{

		printf_P_flush( PSTR("\r\nwaiting for TPM response...") );

		// clear the xfer buffer
		for(i=0; i<numBytes; i++)
			xferBuf[i]=0;

		// wait for TPM to finish command execution
		// production code would want to have (multiple-level) timeouts here
		do{
			data=pollTPM();						// send startBit, slave address/read
		} while(data != MR_SLA_ACK_R);

		/*
		 * all TPM responses are at least 10 bytes, retrieve them
		 * then check the paramSize to see if more are available
		 */

		// first 9 bytes
		for(i=0; i<9; i++)
			xferBuf[i] = read_ACK();

		// extract the paramSize
		// (big/little endian conversion, this is faster than shifting)
		paramSize.bytes[0] = xferBuf[5];
		paramSize.bytes[1] = xferBuf[4];
		numBytes = paramSize.size;

		if(numBytes == 10)
			xferBuf[i++] = read_NAK();		// NAK if 10th is last byte
		else
			xferBuf[i++] = read_ACK();

		if( (numBytes > 1023) || (numBytes < 10) )
		{
			printf_P_flush( PSTR("bad paramSize\r\n") );
			return;							// something's wrong!!
		}

		if(numBytes > 10)
		{
#ifdef TWO_START_BITS
			// get the TPM's attention
			i = 0;
			do{
				data=start_read();									// send startBit, slave address/read
				i++;
			} while((data != MR_SLA_ACK_R) && (i < POLL_NUM));		// give POLL_NUM tries...

	#ifndef NO_STARTBIT_LOG
			if(i > 1)
			{
				printf_P_flush( PSTR("second read startBit took ") );
				logStartTries(i);
				if(i == POLL_NUM)
				{
					printf_P_flush( PSTR("aborting (rcv ACK 2)\r\n") );
					return;
				}
			}
	#endif
#endif
			// get the rest of the response
			for(i=10; i<numBytes-1; i++)
				xferBuf[i]=read_ACK();
			xferBuf[i] = read_NAK();

		}

		// show what we got
		if(wantLog == getLog)
		{
			printf_P_flush( PSTR("\r\nfrom TPM:") );
			dumpXferBuf();
		}
	}
}
//-----------------------------------------------------------------------------
