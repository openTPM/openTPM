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
 * \brief This file contains functions for parsing commands at	the
 * 		development kit level (not the daughter board level).
 * \date June 13, 2011
 * \author Atmel Crypto Products
 */

//#include <avr/pgmspace.h> kmj
#include <string.h>

#include "kitStatus.h"
#include "parserAscii.h"
#include "utilities.h"

/** \brief version of development kit firmware
*/

char VERSION_KIT[]  = {1, 1, 2};
//! version of SHA204 library
char VERSION_ECC108[] = {1, 1, 1};
char STRING_ECC108[]= "SHA204 ";      //!< SHA204 string
device_info_t device_info = {};

char STRING_KIT_SHORT[] = "SAM4S ";         //!< short string of
char STRING_KIT[]  = "ECC SIGNING MODULE ";  //!< long string of


char StringInterface[] = "TWI";


/** \brief This function parses kit commands (ASCII) received from a
 * 			PC host and returns an ASCII response.
 * \param[in] commandLength number of bytes in command buffer
 * \param[in] command pointer to ASCII command buffer
 * \param[out] responseLength pointer to number of bytes in response buffer
 * \param[out] response pointer to binary response buffer
 * \param[out] responseIsAscii pointer to response type
 * \return the status of the operation
 */
uint8_t ParseBoardCommands(uint8_t commandLength, uint8_t *command, uint8_t *responseLength, uint8_t *response, uint8_t *responseIsAscii)
{
	uint8_t status = KIT_STATUS_UNKNOWN_COMMAND;
	uint8_t responseIndex = 0;
	uint8_t deviceIndex;
	uint16_t dataLength = 1;
	uint8_t *rxData[1];

	char *pToken = strchr((char *) command, ':');
	if (!pToken)
		return status;

	*responseIsAscii = 1;

	switch(pToken[1]) {
		case 'v':
			// Gets abbreviated board name, device type, and interface type.
			// response: <kit version>, <device type>, <interface><status>(<address>)

			status = KIT_STATUS_SUCCESS;

			// Copy version string into response buffer.
			strcpy((char *) response, STRING_KIT_SHORT);

			// Append device type to response.

			strcat((char *) response, STRING_ECC108);

			// Append interface type to response.
			strcat((char *) response, StringInterface);
			responseIndex = strlen((char *) response);

			// Append device address / selector byte.
			// Skip one byte for the status.
			dataLength++;
			response[responseIndex + 1] = device_info.address;
			break;


		case 'f':
			// Gets firmware name and version (index 0: kit, 1: SHA204 library, 2: AES132 library).
			status = ExtractDataLoad(pToken, &dataLength, rxData);
			if (status != KIT_STATUS_SUCCESS)
				break;

			dataLength = 4; // size of versions + status byte

			switch (*rxData[0]) {
			case 0: // kit version
				strcpy((char *) response, STRING_KIT);
				responseIndex = strlen((char *) response);
				memcpy((char *) (response + responseIndex + 1), VERSION_KIT, dataLength);
				break;

			case 1: // library version
#ifdef SHA204
				strcpy_P((char *) response, STRING_SHA204);
				responseIndex = strlen((char *) response);
				memcpy_P((char *) (response + responseIndex + 1), VERSION_SHA204, dataLength);
#elif AES132
				strcpy_P((char *) response, STRING_AES132);
				responseIndex = strlen((char *) response);
				memcpy_P((char *) (response + responseIndex + 1), VERSION_AES132, dataLength);
#endif
				break;

			default:
			   dataLength = 1; // size of status byte
				status = KIT_STATUS_INVALID_PARAMS;
				break;
			}
			break;


		case 'd':
			status = ExtractDataLoad(pToken, &dataLength, rxData);
			if (status != KIT_STATUS_SUCCESS)
				break;

			deviceIndex = *rxData[0];
			if (deviceIndex >= DISCOVER_DEVICE_COUNT_MAX) {
				status = KIT_STATUS_INVALID_PARAMS;
				break;
			}

			status = KIT_STATUS_SUCCESS;

			// Copy device type into response.
			strcpy((char *) response, STRING_ECC108);


			// Append interface type to response.
			strcat((char *) response, StringInterface);
			responseIndex = strlen((char *) response);

			// Append the index / address of the device.
			// Skip one byte for status.
			dataLength++;
			response[responseIndex + 1] =
		   device_info.device_index;

			break;


		default:
			status = KIT_STATUS_UNKNOWN_COMMAND;
			break;
	}
	// Append <status>(<data>).
	response[responseIndex] = status;
	*responseLength = CreateUsbPacket(dataLength, &response[responseIndex]) + responseIndex;
	return status;
}
