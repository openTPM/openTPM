#ifndef PHYISCAL_H
#define PHYSICAL_H

// typedefs

typedef enum {noResponse, getResponse} responseAction;
typedef enum {noLog, getLog} logAction;
typedef enum {noCRC, addCRC} crcAction;
typedef enum {noStopBit, sendStopBit} stopBitAction;

// #defines
#define EQ ==
#define NE !=

#define MT	0x00
#define MR	0x01
#define ST	0x02
#define SR	0x04

// Master Transmitter codes
#define MT_START 			0x08
#define MT_REPEAT_START 	0x10
#define MT_SLA_ACK_W 		0x18
#define MT_SLA_NAK_W		0x20
#define MT_DATA_ACK 		0x28
#define MT_DATA_NAK			0x30
#define MT_LOST				0x38

// Master Receiver codes
#define MR_START			0x08
#define MR_REPEAT_START		0x10
#define MR_SLA_LOST			0x38
#define MR_SLA_ACK_R 		0x40
#define MR_SLA_NAK_R		0x48
#define MR_DATA_ACK			0x50
#define MR_DATA_NAK			0x58

// Slave Receive codes
#define SR_SLA_ACK_W		0x60
#define SR_LOST_ACK			0x68
#define SR_DATA_ACK			0x80
#define SR_DATA_NAK			0x88
#define SR_REPEAT_START		0xA0

// Slave Transmit codes
#define ST_SLA_ACK_R		0xA8
#define ST_LOST_ACK			0xB0
#define ST_DATA_ACK			0xB8
#define ST_DATA_NAK			0xC0
#define ST_LAST_DATA_ACK	0xC8

// For reg lock
//register unsigned char R14 asm("r14");
//register unsigned char R15 asm("r15");

// protos

void twi_init(void);
void twi_error(uint8_t errorval);
void start(void);
uint8_t sda_r(void);
uint8_t pollTPM(void);
uint8_t sda_w(void);
uint8_t read(void);
uint8_t write(uint8_t data);
void dumpXferBuf(void);
void logStartTries(uint8_t numTries);
void sendCommand(	responseAction wantResponse,
					logAction wantLog);

void probeTPM(	uint8_t slaveAdd,
				stopBitAction stopBitOption);
				
				
/**
 * \brief Set the specified SPI clock configuration.
 *
 * \param configuration  Index of the configuration to set.
 */
void spi_set_clock_configuration(uint8_t configuration);				
uint8_t spi_master_transfer(uint8_t *p_buf, uint8_t *resp, uint32_t size);
uint8_t spi_transfer(uint8_t *p_buf, uint8_t *resp, uint32_t size);
bool get_moredata_value(void);
bool flush_tpm(void);
void convertHexToAsciiString( uint8_t hexData, char *ptrHexString ); 				
#endif

