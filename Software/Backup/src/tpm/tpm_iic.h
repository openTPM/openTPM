/*
 * tpm_iic.h
 *
 * Created: 3/9/2014 9:47:38 PM
 *  Author: Bruce
 */ 


#ifndef TPM_IIC_H_
#define TPM_IIC_H_


/* TPM device address */
#define TPM_DEVICE_ADDRESS					0x29 /* 7-bit address */

/*! TWI ID for EEPROM application to use */
#define TPM_TWI_MODULE_ID					ID_TWI0

/*! TWI Base for TWI EEPROM application to use */
#define TPM_TWI_MODULE						TWI0

/** TWI Bus Clock 400kHz */
#define TWI_CLK								400000


#endif /* TPM_IIC_H_ */