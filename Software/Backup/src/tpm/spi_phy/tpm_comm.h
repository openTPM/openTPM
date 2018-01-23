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
 *  \brief 	This file contains definitions of hardware independent functions
 *          inside the Physical SPI layer of the SPI TPM library.
 *  \date 	October 4, 2011
 */

#ifndef TPM_COMM_H
#define TPM_COMM_H

#include <stdint.h>

//#define SPI_TPM
#define I2C_TPM

// Define utility numbers (NULL, set, clear)
#ifndef NULL
#define NULL    0
#endif

// Misc defines
#define set		1
#define clear	0
#define TPM_HEADER_SIZE	10

// TPM operations function prototypes
uint8_t tpmCommandWrite(uint16_t count, uint8_t *data);
uint8_t tpmCommandRead(uint16_t *responseLength, uint8_t *response);
uint8_t tpmTIS_write(uint8_t count, uint8_t *word_address, uint8_t *data);
uint8_t tpmTIS_read(uint8_t count, uint8_t *word_address, uint16_t *responseLength, uint8_t *response);

uint8_t tpmSetResetPin(uint8_t state);
uint8_t tpmSetSsPin(uint8_t state);
uint8_t tpmSetAuxPin(uint8_t state);
uint8_t tpmReadResetPin(uint8_t* state);
uint8_t tpmReadSsPin(uint8_t* state);
uint8_t tpmReadAuxPin(uint8_t* state);
uint8_t tpmReadPirqPin(uint8_t* state);
uint8_t tpmReadGpioPin(uint8_t* state);


#endif
