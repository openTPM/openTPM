/**
 * \file
 *
 * \brief User board configuration template
 *
 */
/*
 * Support and FAQ: visit <a href="http://www.atmel.com/design-support/">Atmel Support</a>
 */

#ifndef CONF_BOARD_H
#define CONF_BOARD_H

/* The SAM4S Xplain has one push button only */
#define BOARD_NO_PUSHBUTTON_2

/* Configure ADC example pins */

#ifdef SPI_INTERFACE

/* Configure SPI pins */
#define CONF_BOARD_SPI
#define CONF_BOARD_SPI_NPCS0

/* Spi Hw ID */
#define SPI_ID          ID_SPI

/* SPI base address for SPI master mode */
#define SPI_MASTER_BASE      SPI
#endif

#ifdef TWI_INTERFACE
/* Configure TWI pins */
#define CONF_BOARD_TWI0
#endif

/* Internal FLASH Programming Support */
#define IFLASH_PAGE_SIZE  IFLASH0_PAGE_SIZE
#define IFLASH_PAGE_SIZE_INWORDS (IFLASH_PAGE_SIZE/4)

/* Last page start address. */
#define LAST_PAGE_ADDRESS (IFLASH1_ADDR + IFLASH_SIZE - IFLASH_PAGE_SIZE * 8)

#endif // CONF_BOARD_H
