TWI Demo for TPM

The source code provided is intended to demonstrate implementation of basic TPM operations.  The TPM related functions have been added to an existing Atmel demonstration program for the AT90USBKey platform.  The AT90USBKey software includes the initialization, task management, and USB (virtual UART) drivers that provide the operating environment for the TPM demo software.

As the AT90USBKey documentation is provided in the TPM Starter Kit, the answers to any questions related to that system can be located in there.  This document is intended to explain how the TPM demo software operates so that a developer can quickly grasp the overall architecture of the software.

After the AT90USBKey software boots the AT90USB1287 AVR microcontroller, it invokes a scheduler which controls two tasks: a USB task (for dealing with USB initialization, enumeration, etc.), and the TPM demo task which controls execution of the TPM demo.  After each command invocation, the scheduler is re-entered which eventually calls the TPM demo task again.

The TPM demo has a simple menu function which invokes the central demo execution function, commandHandler.  The commandHandler function executes the desired operation by looking up the command template, function pointer and authorization parameters from a central table of TPM_Command structures, commandTable.  It initializes the TPM IO buffer from the stored command template, then dispatches the command function through the function pointer contained in the table.  It is possible for commands to invoke other commands through commandHandler; in fact that is how the sequenced menu functions are executed by the top level functions in the demo software.

Once the command function has been dispatched, it controls execution of the desired operation.  The commandTable pointer is passed to this function so that it has access to the command template data and the authorization parameters contained in the TPM_Command structure pointer.  The sequencing of the command function may involve invocations of other commands through commandHandler.

If the command being executed involves authorization, then the command function invokes authorization handling functions to calculate the required input authorization data before and output authorization validation data after the command itself is sent to the TPM.

Some command functions request user input, the user responses are used to generate the TPM command parameters subsequently sent to the TPM.  Authorization input is hashed through the SHA-1 function to generate the actual authorization values used.  Other input is used directly (such as seal and signature input).

Once the IO buffer has been filled with the TPM bytes, the data is sent to the TPM by invocation of the top level TWI (two-wire interface) function, sendCommand.  The sendCommand function invokes lower-level TWI functions in order to generate the start bit, device address, and command data waveforms through the AVR hardware.  After sending the command data, it then polls the TPM busy status (ACK polling) until the TPM responds to a TWI read request.  Once the TPM responds, sendCommand reads back the TPM's response into the IO buffer.

The TPM response data often contains information that must be saved for future use.  The TPM demo allocates the AVR EEPROM space into several fixed-size "slots" which are used to cache TPM keys, sealed blobs, and signature data.  The user is prompted to indicate the "slot" number to store the data into.   Additionally, the EEPROM is used to store the key handles and authorization data for keys currently loaded into the TPM.

Since the EEPROM data is non-volatile, it is able to track the TPM contents; when the TPM is cleared or a key is flushed the demo software performs the corresponding action on the data stored in AVR EEPROM.

The demo software should provide useful examples of simple key management, authorization calculation and verification, and basic TPM sequence of operations.  It is not intended to demonstrate best-practice operation in all TPM operating environments; the source code comments indicate in several instances where it may be necessary to implement more secure methods of operation.

