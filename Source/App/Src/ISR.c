/************************************************************************************
** File: - E:\ARM\lm3s8962projects\MatrixSSL\Source\App\Src\ISR.c
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      the Interrupt Service
** 
** Version: 1.2
** Date created: 17:34:24,14/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/


//****************************************************************************
//
// The interrupt handler for the SysTick interrupt.
//
//****************************************************************************
void SysTickIntHandler(void)
{
    //
    // Indicate that a SysTick interrupt has occurred.
    //
    HWREGBITW(&g_ulFlags, FLAG_SYSTICK) = 1;
    g_ulSysTickCounter++;

    //
    // Call the lwIP timer handler.
    //
    lwIPTimer(SYSTICKMS);

    //
    // Run the file system tick.
    //
    fs_tick(SYSTICKMS);
    g_ulfsTickCounter++;
}



//*****************************************************************************
//
// Required by lwIP library to support any host-related timer functions.
//
//*****************************************************************************
void lwIPHostTimerHandler(void)
{
    static unsigned long ulLastIPAddress = 0;
    unsigned long ulIPAddress;

    ulIPAddress = lwIPLocalIPAddrGet();

    //
    // If IP Address has not yet been assigned, update the display accordingly
    //
    if(ulIPAddress == 0)
    {
        static int iColumn = 6;

        //
        // Update status bar on the display.
        //
        DisplayEnable(1000000);
        if(iColumn < 12)
        {
            DisplayStringDraw("< ", 0, 24, 15);
            DisplayStringDraw("*",iColumn, 24, 7);
        }
        else
        {
            DisplayStringDraw(" *",iColumn - 6, 24, 7);
        }

        iColumn+=2;
        if(iColumn > 114)
        {
            iColumn = 6;
            DisplayStringDraw(" >", 114, 24, 15);
        }
        DisplayDisable();
    }

    //
    // Check if IP address has changed, and display if it has.
    //
    else if(ulLastIPAddress != ulIPAddress)
    {
        ulLastIPAddress = ulIPAddress;
        DisplayEnable(1000000);
        DisplayStringDraw("                       ", 0, 16, 15);
        DisplayStringDraw("                       ", 0, 24, 15);
        DisplayStringDraw("IP:   ", 0, 16, 15);
        DisplayStringDraw("MASK: ", 0, 24, 15);
        DisplayStringDraw("GW:   ", 0, 32, 15);
        DisplayIPAddress(ulIPAddress, 36, 16);
        ulIPAddress = lwIPLocalNetMaskGet();
        DisplayIPAddress(ulIPAddress, 36, 24);
        ulIPAddress = lwIPLocalGWAddrGet();
        DisplayIPAddress(ulIPAddress, 36, 32);
        DisplayDisable();
    }
}




