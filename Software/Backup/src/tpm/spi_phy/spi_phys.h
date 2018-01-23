// ----------------------------------------------------------------------------
//         ATMEL Crypto-Devices Software Support  -  Colorado Springs, CO -
// ----------------------------------------------------------------------------
// DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
// DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------------------

/** \file
 *  \brief Header file for spi_phys.c.
 *  \author Atmel Crypto Products
 *  \date  February 2, 2011
 */

#ifndef SPI_PHYS_H_
#define SPI_PHYS_H_

#include <stdint.h>

// error codes for physical hardware dependent module
// Codes in the range 0x00 to 0xF7 are shared between physical interfaces (SWI, I2C, SPI).
// Codes in the range 0xF8 to 0xFF are special for the particular interface.
#define SPI_FUNCTION_RETCODE_SUCCESS     ((uint8_t) 0x00) //!< Communication with device succeeded.
#define SPI_FUNCTION_RETCODE_COMM_FAIL   ((uint8_t) 0xF0) //!< Communication with device failed.
#define SPI_FUNCTION_RETCODE_TIMEOUT     ((uint8_t) 0xF1) //!< Communication timed out.

// When porting to a different target than an AVR 8-bit micro-controller,
// replace the port macros with the ones your target library uses.
// Add more macro definitions for the chip selects (e.g. SPI_CS_0)
// if you use more than one device.
#define SPI_PIN_OUT       PINB	  //!< port pin register
#define SPI_PORT_OUT      PORTB   //!< port output register
#define SPI_PORT_DDR      DDRB    //!< port direction register
#define SPI_SS            (1)     //!< register bit 0 (1<<0) for slave select of first device (pin 1)
#define SPI_CLOCK         (2)     //!< register bit 1 (1<<1) for clock (pin 2)
#define SPI_MOSI          (4)     //!< register bit 2 (1<<2) for Master-Out-Slave-In (pin 3)
#define SPI_MISO          (8)     //!< register bit 3 (1<<3) for Master-In-Slave-Out (pin 4)

#define TPM_RESET         (16)    //!< register bit 4 (1<<4)
#define TPM_AUX           (32)    //!< register bit 5 (1<<5)
#define TPM_PIRQ          (64)    //!< register bit 6 (1<<6)
#define TPM_GPIO1         (128)   //!< register bit 7 (1<<7)

#define SPI_DEVICE_COUNT  (1)     //!< number of SPI devices

void    spi_enable(void);
void    spi_disable(void);
void    spi_select_slave(void);
void    spi_deselect_slave(void);
uint8_t spi_select_device(uint8_t index);
uint8_t spi_send_bytes(uint8_t count, uint8_t *data);
uint8_t spi_receive_bytes(uint8_t count, uint8_t *data);
uint8_t spi_get_MISO(void);

void    spi_tpm_enable(void);
uint8_t spi_get_pin(uint8_t pinBit);
void	spi_set_pin(uint8_t pinBit, uint8_t state);

#endif
