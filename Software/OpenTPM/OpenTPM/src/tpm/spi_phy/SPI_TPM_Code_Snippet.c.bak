Here is the C# logic that uses the register  read/write to send commands to the TPM.

protected void WriteCommand(Hexstring data)
{
       if (data == null)
       {
              WriteConsoleErrorLine("TpmMicrobaseDriver.WriteCommand: data is NULL.");
       }
       else if (data.Length == 0)
       {
              WriteConsoleErrorLine("TpmMicrobaseDriver.WriteCommand: data.Length = 0.");
       }
       // Wait for clear communication
       clearCommSignal.WaitOne();

       // Be sure we have locality
       byte accessByte = AccessRegister;
       if ((accessByte & (byte)AccessBit.LocalityActive) != (byte)AccessBit.LocalityActive)
       {
              // We don't have locality, set the locality
              Locality = locality;
       }
       // Tell the TPM we are ready to send a command twice.
       // The first potenitally interrupts the background keygen
       // The second tells the TPM to expect a command
       StatusRegister = (byte)StatusBit.CommandReady;
       StatusRegister = (byte)StatusBit.CommandReady;

       // Wait for the TPM to say its ready to receive the command.
       uint timeout = 1;
       byte statusByte = StatusRegister;
       bool waitingMsg = false;
       consoleOn = false;
       // Wait for command ready
       while ((statusByte & (byte)StatusBit.CommandReady) != (byte)StatusBit.CommandReady)
       {
              System.Threading.Thread.Sleep(100);
              timeout++;
              if (timeout == 30)
              {
                     WriteConsole("\r\n", true);
                     throw new DriverException(DriverException.ErrorCode.DriverError, "Timed out waiting for \"CommandReady\" in TpmMicrobaseDriver.Write");
              }
              if (timeout == 5)
              {
                     waitingMsg = true;
                     WriteConsole("Waiting for Command Ready...", true);
              }
              if (timeout % 5 == 1 && Parameters.PrintDots)
              {
                     WriteConsole(".", true);
              }
              statusByte = StatusRegister;
       }
       consoleOn = true;
       if (waitingMsg) WriteConsole("\r\n", true);

       // Send the command bytes to the FIFO 64 bytes at a time
       int sent = 0;
       while (sent < data.Length)
       {
              SetRegisterValue(TISRegister.FIFO64, data.Substring(sent, 64));
              sent += 64;
       }
       // If we have written all the command data to the TPM, but the TPM is expecting more data,
       // the command was constructed incorrectly and has too little data.
       statusByte = StatusRegister;
       if ((statusByte & (byte)StatusBit.DataExpected) == (byte)StatusBit.DataExpected)
       {
              WriteConsoleErrorLine("TpmMicrobaseDriver.WriteCommand: More data expected");
              //throw new DriverException(DriverException.ErrorCode.DataWriteUnderrun, data.Data);
       }
       // Tell the TPM to execute the command.
       StatusRegister = (byte)StatusBit.Execute;
}

protected Hexstring ReadCommand()
{
       // Wait for the TPM to become ready for reading data.
       uint timeout = 1;
       byte statusByte = StatusRegister;
       bool waitingMsg = false;
       consoleOn = false;
       while ((statusByte & (byte)StatusBit.DataAvailable) != (byte)StatusBit.DataAvailable)
       {
              System.Threading.Thread.Sleep(100);
              timeout++;
              if (timeout == 2000)
              {
                     WriteConsole("\r\n", true);
                     throw new DriverException(DriverException.ErrorCode.DriverError, "Timed out while attempting to read from the TPM. (DataAvailable bit was never set)");
              }
              // After 5 times through the loop, print "Waiting for Data Available......." to the console
              if (timeout == 5)
              {
                     waitingMsg = true;
                     WriteConsole("Waiting for Data Available...", true);
              }
              if (timeout % 5 == 1 && Parameters.PrintDots)
              {
                     WriteConsole(".", true);
              }
              if (timeout % 200 == 0 && Parameters.PrintDots)
              {
                     WriteConsole("\r\n", true);
              }
              statusByte = StatusRegister;
       }
       consoleOn = true;
       if (waitingMsg) WriteConsole("\r\n", true);

       // Read the first 10 bytes of the TPM response
       uint bytesRead = 10;
       Hexstring response = GetRegisterData(TISRegister.FIFO64, bytesRead);
       TpmCommand tpmCmd = new TpmCommand(response);
       while (bytesRead < tpmCmd.ParamSize)
       {
              // Read the FIFO register contents up to 64 bytes at a time
              uint bytesToRead = Math.Min(64, tpmCmd.ParamSize - bytesRead);
              response += GetRegisterData(TISRegister.FIFO64, bytesToRead);
              bytesRead += bytesToRead;
       }
       // Send a "Command Ready" to tell the TPM that all the data has been read.
       StatusRegister = (byte)StatusBit.CommandReady;
       return response;
}


