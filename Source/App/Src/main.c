/************************************************************************************
** File: - E:\ARM\lm3s8962projects\MatrixSSL\Source\App\Src\main.c
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      WebServer using SSL
** 
** Version: 1.1
** Date created: 12:44:04,20/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#include "hw_memmap.h"
#include "hw_types.h"
#include "hw_ints.h"
#include "ethernet.h"
#include "interrupt.h"
#include "sysctl.h"
#include "systick.h"
#include "flash.h"
#include "gpio.h"
#include "timer.h"
#include "ustdlib.h"
#include "uartstdio.h"
#include "display.h"
#include "lwiplib.h"
#include "httpsd.h"
#include "ssl.h"


//*****************************************************************************
//
//! \addtogroup example_list
//! <h1>SSL Web Server (webserver-ssl)</h1>
//!
//! This example application demonstrates the operation of the Stellaris
//! Ethernet controller using the lwIP TCP/IP Stack and MatrixSSL library.
//! DHCP is used to obtain an ethernet address.  If DHCP times out without
//! obtaining an address, an IP address is automatically allocated using the
//! RFC3927 automatic link-local IP address allocation algorithm. The address
//! that is selected will be shown on the OLED display.
//!
//! The file system code will first check to see if an SD card has been plugged
//! into the microSD slot.  If so, all file requests from the web server will
//! be directed to the SD card.  Otherwise, a default set of pages served up
//! by an internal file system will be used.
//!
//! Requests may be made using HTTPS on port 443 (the default). Unencrypted
//! HTTP is not supported in this example.
//
//*****************************************************************************

//*****************************************************************************
//
// Debug variables.
//
//*****************************************************************************
unsigned long g_ulLoopCounter = 0;
unsigned long g_ulSysTickCounter = 0;
unsigned long g_ulEthRxCounter = 0;
unsigned long g_ulEthTxCounter = 0;
unsigned long g_ulfsTickCounter = 0;
unsigned long g_ulEthRxOverflowCount = 0;
unsigned long g_ulEthRxErrorCount = 0;


//*****************************************************************************
//
// Defines for setting up the system clock.
//
//*****************************************************************************
#define SYSTICKHZ               100
#define SYSTICKMS               (1000 / SYSTICKHZ)
#define SYSTICKUS               (1000000 / SYSTICKHZ)
#define SYSTICKNS               (1000000000 / SYSTICKHZ)


//*****************************************************************************
//
// A set of flags.  The flag bits are defined as follows:
//
//     0 -> An indicator that a SysTick interrupt has occurred.
//     1 -> An RX Packet has been received.
//     2 -> An RX Packet has been received.
//
//*****************************************************************************
#define FLAG_SYSTICK            0
#define FLAG_RXPKT              1
#define FLAG_TXPKT              2
static volatile unsigned long g_ulFlags;


//*****************************************************************************
//
// External Application references.
//
//*****************************************************************************
extern err_t ethernetif_init(struct netif *netif);
extern void ethernetif_input(struct netif *netif);
extern void fs_init(void);
extern void fs_tick(unsigned long ulTickMS);
extern void luminaryif_debug_init(void);
extern void sslSetHardwareTimer(unsigned long ulTimerBase);


//*****************************************************************************
//
// The error routines that are called if runtime libraries encounter an error.
//
//*****************************************************************************
#ifdef DEBUG
void
__error__(char *pcFilename, unsigned long ulLine)
{
    UARTprintf("Runtime error at line %d of %s\n", ulLine, pcFilename);
    while(1);
}


//
// In a debug build, dump a helpful message when an assert failure is
// detected then hang in a tight loop.
//
void
__assert(const char *pcFile, int iLine, const char *pcMsg)
{
    UARTprintf("Assert failure at line %d of %s\n", iLine, pcFile);
    while(1);
}
#else
//
// In a release build, an assert failure merely hangs the caller.
//
void
__assert(const char *pcFile, int iLine, const char *pcMsg)
{
    while(1);
}
#endif


//****************************************************************************
//
// Application has exited. This function is called in case of some fatal error
// conditions.
//
//****************************************************************************
void
AppExit(int iExit)
{
	while (1);
}


//****************************************************************************
//
// The interrupt handler for the SysTick interrupt.
//
//****************************************************************************
void
SysTickIntHandler(void)
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
// Display an lwIP type IP Address.
//
//*****************************************************************************
void
DisplayIPAddress(unsigned long ipaddr, unsigned long ulCol,
                 unsigned long ulRow)
{
    char pucBuf[16];
    unsigned char *pucTemp = (unsigned char *)&ipaddr;

    //
    // Convert the IP Address into a string.
    //
    usprintf(pucBuf, "%d.%d.%d.%d", pucTemp[0], pucTemp[1], pucTemp[2],
             pucTemp[3]);

    //
    // Display the string.
    //
    DisplayStringDraw(pucBuf, ulCol, ulRow, 15);
}


//*****************************************************************************
//
// Should be called by the top-level application to perform the needed
// lwIP TCP/IP and matrixSSL initialization.
//
//*****************************************************************************
void
app_network_init(unsigned char *pucMACArray)
{
    int iRet;

    //
    // Initialize our debug interface if required. This must be done before
    // lwip_init is called.
    //
    #ifdef LWIP_DEBUG

    //
    // Enable the peripherals used by this example.
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA);

    //
    // Ensure that UART0 is connected to the appropriate outputs.
    //
    GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

    //
    // Initialize the UART standard IO module that is used to generate the
    // debug output.
    //
    UARTStdioInit(0);

    #endif

    //
    // Initialize the SSL layer. Note that the implementation of malloc used
    // by both the SSL layer and lwIP is within the matrixSsl osLayer
    // implementation so we need to initialise SSL before lwIP to ensure that
    // the heap is set up before anyone tries to allocate from it.
    //
    iRet = ssl_init();
    if(iRet != 0)
    {
        //
        // Oops - something went wrong while trying to initialize the SSL
        // library.
        //
        UARTprintf("Error initializing SSL!\n");
        AppExit(1);
    }

    //
    // Low-Level initialization of the lwIP stack modules.
    //
    lwIPInit(pucMACArray, 0, 0, 0, IPADDR_USE_DHCP);
}


//*****************************************************************************
//
// Required by lwIP library to support any host-related timer functions.
//
//*****************************************************************************
void
lwIPHostTimerHandler(void)
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


//****************************************************************************
//
// This example demonstrates the use of the Ethernet Controller.
//
//*****************************************************************************
int
main(void)
{
    unsigned long ulUser0, ulUser1;
    unsigned char pucMACArray[8];

    //
    // Set the clocking to run from the PLL at 50MHz.
    //
    SysCtlClockSet(SYSCTL_SYSDIV_4 | SYSCTL_USE_PLL | SYSCTL_OSC_MAIN |
                   SYSCTL_XTAL_8MHZ);

    //
    // Initialize the OLED display.
    //
    DisplayInit(1000000);
    DisplayEnable(1000000);
    DisplayStringDraw("SSL Web Server", 14, 0, 15);
    DisplayDisable();

    //
    // Initialize UART0 for printf output.
    //
    UARTStdioInit(0);

    //
    // Check for presence of Ethernet Controller.
    //
    if(!SysCtlPeripheralPresent(SYSCTL_PERIPH_ETH))
    {
        DisplayEnable(1000000);
        DisplayStringDraw("Ethernet Controller", 0, 16, 15);
        DisplayStringDraw("Not Found!", 0, 24, 15);
        DisplayDisable();
        AppExit(1);
    }

    //
    // Enable and Reset the Ethernet Controller.
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_ETH);
    SysCtlPeripheralReset(SYSCTL_PERIPH_ETH);

    //
    // Enable Port F for Ethernet LEDs.
    //  LED0        Bit 3   Output
    //  LED1        Bit 2   Output
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);
    GPIODirModeSet(GPIO_PORTF_BASE, GPIO_PIN_2 | GPIO_PIN_3, GPIO_DIR_MODE_HW);
    GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_2 | GPIO_PIN_3,
                     GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD);

    //
    // Configure SysTick for a periodic interrupt.
    //
    SysTickPeriodSet(SysCtlClockGet() / SYSTICKHZ);
    SysTickEnable();
    SysTickIntEnable();

    //
    // Enable Timer0 for use as the SSL library time source and let the SSL
    // library know which timer to use.
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER0);
    sslSetHardwareTimer(TIMER0_BASE);

#ifdef DEBUG
    //
    // In debug builds, make sure that timer 0 stalls when the debugger has
    // control. This makes single stepping somewhat easier since you are less
    // likely to find yourself dumped into the ISR unexpectedly while stepping
    // through non-exception code.
    //
    TimerControlStall(TIMER0_BASE, TIMER_BOTH, true);
#endif

    //
    // Enable processor interrupts.
    //
    IntMasterEnable();

    //
    // Configure the hardware MAC address for Ethernet Controller filtering of
    // incoming packets.
    //
    // For the LM3S6965 Evaluation Kit, the MAC address will be stored in the
    // non-volatile USER0 and USER1 registers.  These registers can be read
    // using the FlashUserGet function, as illustrated below.
    //
    FlashUserGet(&ulUser0, &ulUser1);
    if((ulUser0 == 0xffffffff) || (ulUser1 == 0xffffffff))
    {
        //
        // We should never get here.  This is an error if the MAC address
        // has not been programmed into the device.  Exit the program.
        //
        DisplayEnable(1000000);
        DisplayStringDraw("MAC Address", 0, 16, 15);
        DisplayStringDraw("Not Programmed!", 0, 24, 15);
        DisplayDisable();
        AppExit(2);
    }

    //
    // Convert the 24/24 split MAC address from NV ram into a 32/16 split
    // MAC address needed to program the hardware registers, then program
    // the MAC address into the Ethernet Controller registers.
    //
    pucMACArray[0] = ((ulUser0 >>  0) & 0xff);
    pucMACArray[1] = ((ulUser0 >>  8) & 0xff);
    pucMACArray[2] = ((ulUser0 >> 16) & 0xff);
    pucMACArray[3] = ((ulUser1 >>  0) & 0xff);
    pucMACArray[4] = ((ulUser1 >>  8) & 0xff);
    pucMACArray[5] = ((ulUser1 >> 16) & 0xff);

    //
    // Program the hardware with it's MAC address (for filtering).
    //
    EthernetMACAddrSet(ETH_BASE, pucMACArray);

    //
    // Initialize the file system.
    //
    DisplayDisable();
    fs_init();

    //
    // Initialize all of the lwIP code, as needed, which will
    // also initialze the low-level ethernet code.
    //
    app_network_init(pucMACArray);

    //
    // Initialize the sample SSL web server.
    //
    httpsd_init();

    //
    // Main Application Loop (for systems with no RTOS).
    // Run every SYSTICK.
    //
    while(true)
    {
        //
        // Put the processor to sleep.
        //
        SysCtlSleep();
        g_ulLoopCounter++;
    }
}

