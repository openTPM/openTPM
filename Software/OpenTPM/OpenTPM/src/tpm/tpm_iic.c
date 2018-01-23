/*
 * tpm_iic.c
 *
 * Created: 3/9/2014 9:47:56 PM
 *  Author:
 */ 

#ifdef TWI_INTERFACE

#include <asf.h>

// 
// void()
// 
// 	asm("NOP");
// 	#ifdef TWI_INTERFACE
// 
// 	/* Enable the peripheral clock for TWI */
// 	pmc_enable_periph_clk(TPM_TWI_MODULE_ID);
// 
// 	twi_options_t opt = {
// 		.master_clk = sysclk_get_cpu_hz(),
// 		.speed = TWI_CLK,
// 		.chip  = TPM_DEVICE_ADDRESS
// 	};
// 	
// 	
// 	/* Configure the data packet to be transmitted */
// 	packet_tx.chip        = TPM_DEVICE_ADDRESS;
// 	packet_tx.addr[0]     = 0x00;
// 	packet_tx.addr[1]     = 0x00;
// 	packet_tx.addr_length = 0x00;
// 	packet_tx.buffer      = (uint8_t *) tpm_iic_test_data;
// 	packet_tx.length      = IIC_TEST_DATA_LENGTH;
// 
// 	/* Configure the data packet to be received */
// 	packet_rx.chip        = packet_tx.chip;
// 	packet_rx.addr[0]     = 0x00;
// 	packet_rx.addr[1]     = 0x00;
// 	packet_rx.addr_length = 0x00;
// 	packet_rx.buffer      = data_rx;
// 	packet_rx.length      = packet_tx.length;
// 
// 	if (twi_master_setup(TPM_TWI_MODULE, &opt) != TWI_SUCCESS) {
// 		/* to-do, error handling */
// 		while(1);
// 	}
// 
// 	#else // SPI
// 	spi_set_clock_configuration(0);
// 	#endif
// 
// 	/* probe TWI address */
// 	//twi_probe(TPM_TWI_MODULE, TPM_DEVICE_ADDRESS);
// 	asm("NOP");
// 
// 	/* IIC command */
// 	twi_master_write(TPM_TWI_MODULE, &packet_tx);
// 	
// 	/* read TPM response */
// 	retry = 10;
// 	do
// 	{	/* perform ACK polling if necessary */
// 		if(twi_master_read(TPM_TWI_MODULE, &packet_rx)  == TWI_SUCCESS)
// 		{
// 			break;
// 		}
// 		delay_ms(5);
// 	} while (retry--);
// 
// 
// 
// 
// 
// 






#endif
