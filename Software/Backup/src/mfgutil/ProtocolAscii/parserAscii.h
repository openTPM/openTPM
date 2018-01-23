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
 *  \brief Header file used by ASCII parser modules.
 * \author Atmel Crypto Products
 * \date April 29, 2013
 */

#ifndef _PARSER_ASCII_H_
#   define _PARSER_ASCII_H_

#include <stdint.h>

//! Commands and responses are terminated by this character.
#define KIT_EOP							       ((uint8_t)'\n')

//! \todo Make USB buffer handling capable of uint16_t.

#   define USB_BUFFER_SIZE_TX                  (500)
#   define USB_BUFFER_SIZE_RX                  (500)
#   define DISCOVER_DEVICE_COUNT_MAX             (2)

// -5: two bytes for the kit status, two bytes for the parentheses, and one byte for EOP
#define DEVICE_BUFFER_SIZE_MAX_RX              (uint8_t) ((USB_BUFFER_SIZE_TX - 5) / 2)


//! enumeration for device types
typedef enum {
		DEVICE_TYPE_UNKNOWN,   //!< unknown device
		DEVICE_TYPE_CM,        //!< CM, currently not supported
		DEVICE_TYPE_CRF,       //!< CRF, currently not supported
		DEVICE_TYPE_CMC,       //!< CMC, currently not supported
		DEVICE_TYPE_SA100S,    //!< SA100S, can be discovered, but is currently not supported
		DEVICE_TYPE_SA102S,    //!< SA102S, can be discovered, but is currently not supported
		DEVICE_TYPE_SA10HS,    //!< SA10HS, can be discovered, but is currently not supported
		DEVICE_TYPE_SHA204,    //!< SHA204 device
		DEVICE_TYPE_AES132,    //!< AES132 device
		DEVICE_TYPE_ECC108     //!< ECC108 device
} device_type_t;


//! enumeration for interface types
typedef enum {
	DEVKIT_IF_UNKNOWN,
	DEVKIT_IF_SPI,
	DEVKIT_IF_I2C,
	DEVKIT_IF_SWI,
	DEVKIT_IF_UART
} interface_id_t;


//! information about a discovered device
typedef struct {
	//! interface type (SWI, I2C, SPI)
	interface_id_t bus_type;

	//! device type
	device_type_t device_type;

	//! I2C address or selector byte
	uint8_t address;

	//! array index into GPIO structure for SWI and SPI (Microbase does not support this for SPI.)
	uint8_t device_index;

	//! revision bytes (four bytes for SHA204 and ECC108, first two bytes for AES132)
	uint8_t dev_rev[4];
} device_info_t;


interface_id_t discover_devices();
device_info_t *get_device_info(uint8_t index);
device_type_t get_device_type(uint8_t index);

uint8_t *GetRxBuffer(void);
uint8_t *ResetRxBuffer(uint8_t reset_value);
uint8_t CollateUsbPacket(uint8_t count, uint8_t **buffer);
uint8_t *ProcessUsbPacket(uint16_t *txLength);
uint16_t CreateUsbPacket(uint16_t length, uint8_t *buffer);
uint8_t ParseBoardCommands(uint8_t commandLength, uint8_t *command, uint8_t *responseLength, uint8_t *response, uint8_t *responseIsAscii);
uint8_t ParseEccCommands(uint16_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response);
uint8_t ParseAesCommands(uint8_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response);
uint8_t ParseShaCommands(uint16_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response);
uint8_t ParseSaCommands(uint16_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response);
uint8_t ParseBusCommands(uint8_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response);
uint8_t ParseTsCommands(uint8_t commandLength, uint8_t *command, uint8_t *responseLength, uint8_t *response,uint8_t *responseIsBinary);

#endif
