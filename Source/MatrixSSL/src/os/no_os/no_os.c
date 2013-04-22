/*
 *    no_os.c
 *
 *    A simple "OS" layer for use in systems which are not running an RTOS.
 *  This implementation was prepared by Luminary Micro Inc based on an example
 *  for Linux from PeerSec Networks.
 */
/*    Copyright (c) PeerSec Networks, 2002-2007. All Rights Reserved.
 *    The latest version of this code is available at http://www.matrixssl.org
 *
 *    This software is open source; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This General Public License does NOT permit incorporating this software
 *    into proprietary programs.  If you are unable to comply with the GPL, a
 *    commercial license for this software may be purchased from PeerSec Networks
 *    at http://www.peersec.com
 *
 *    This program is distributed in WITHOUT ANY WARRANTY; without even the
 *    implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *    See the GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *    http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/
#include "../osLayer.h"

/*
#include "../../../../../StellarisWare/third_party/bget/bget.h"
#include "../../../../../StellarisWare/inc/hw_types.h"
#include "../../../../../StellarisWare/inc/hw_memmap.h"
#include "../../../../../StellarisWare/inc/hw_ints.h"
#include "../../../../../StellarisWare/driverlib/timer.h"
#include "../../../../../StellarisWare/driverlib/flash.h"
#include "../../../../../StellarisWare/driverlib/sysctl.h"
#include "../../../../../StellarisWare/driverlib/interrupt.h"
#include "../../../../../StellarisWare/utils/uartstdio.h"
*/

#include "bget.h"
#include "hw_types.h"
#include "hw_memmap.h"
#include "hw_ints.h"
#include "timer.h"
#include "flash.h"
#include "sysctl.h"
#include "interrupt.h"
#include "uartstdio.h"

#ifdef DEBUG
//#include "../../../../../StellarisWare/driverlib/debug.h"
#include "debug.h"
#endif

//*****************************************************************************
//
// Multi-threading cannot be supported in the absence of an OS so catch
// this early and generate a compiler error.
//
//*****************************************************************************
#ifdef USE_MULTITHREADING
#error Multi-threading support not available without an OS.
#endif

//*****************************************************************************
//
// Set aside sufficient memory to act as the runtime heap for the SSL library.
// Note that we declare this in terms of "unsigned longs" to ensure that the
// heap is aligned on a word boundary. This is vital!
//
//*****************************************************************************
static unsigned long g_pcSSLHeap[MAX_SSL_HEAP_SIZE/sizeof(unsigned long)];

#ifdef DEBUG
//*****************************************************************************
//
// Globals allowing us to keep track of SSL heap usage in debug builds.
//
//*****************************************************************************
bufsize g_CurAlloc;
bufsize g_TotFree;
bufsize g_MaxFree;
bufsize g_MallocCount;
bufsize g_FreeCount;
bufsize g_OverCommit;
bufsize g_MinFree = 0x20000;
#endif

//*****************************************************************************
//
// Globals related to the hardware timer we use to track system time.
//
//*****************************************************************************
static unsigned long g_ulSslTimerBase = TIMER0_BASE;
static unsigned long g_ulSslTimerPeriph = SYSCTL_PERIPH_TIMER0;
static unsigned long g_ulSslTimerInt = INT_TIMER0A;
static volatile unsigned long g_ulSeconds = 0;
static unsigned long g_ulClockRate;
static tBoolean g_bSslTimerInitialized = false;

//*****************************************************************************
//
// The number of elapsed seconds which, if exceeded, will cause overflow in
// the seconds-to-milliseconds calculation in sslDiffMsecs.
//
//*****************************************************************************
#define MAX_OVERFLOW_FREE_SECONDS (0x7FFFFFFF / 1000)

//*****************************************************************************
//
// The bit mask of the polynomial bits used in the random number sequence.
//
//*****************************************************************************
#define LSFR_PATTERN        (0x10350103)

//*****************************************************************************
//
// The maximum possible random number provided by the rand() function.
//
//*****************************************************************************
#define MAX_RAND            (0xffffffff)

//*****************************************************************************
//
// The current value of the random number lsfr shift register.
//
//*****************************************************************************
static unsigned long g_ulRandRegister;

//*****************************************************************************
//! Used to seed the pseudo random number generator.
//!
//! \param ulSeed
//!     The seed value for the random number generator.
//!
//*****************************************************************************
static void
SeedRandom(unsigned long ulSeed)
{
    g_ulRandRegister = ulSeed;
}
 
//*****************************************************************************
//! Used to generate a pseudo random number.
//!
//! \return
//!     Returns a value between 0 and MAX_RAND.
//!
//*****************************************************************************
static unsigned long
GetRandom(void)
{
    if(g_ulRandRegister & 1)
    {
        g_ulRandRegister = (g_ulRandRegister >> 1) | 0x80000000;
        g_ulRandRegister ^= LSFR_PATTERN;
    }
    else
    {
        g_ulRandRegister = g_ulRandRegister >> 1;
    }
    return(g_ulRandRegister);
}

//*****************************************************************************
//
//! Handles the interrupt from the SSL library's hardware timer.
//!
//! \param None.
//!
//! This function increments the elapsed seconds counter used to provide a
//! time reference to the SSL library.
//!
//! \Returns None.
//
//*****************************************************************************
void
SslTimerIntHandler(void)
{
    //
    // Clear all pending interrupts from our timer
    //
    TimerIntClear(g_ulSslTimerBase, TimerIntStatus(g_ulSslTimerBase, true));

    //
    // Increment our elapsed second counter.
    //
    g_ulSeconds++;
}

//*****************************************************************************
//
//! C runtime abort function.
//!
//! \param None.
//! parameter is ignored.
//!
//! This function is called in various C runtime library error conditions.
//! Although libc.a appears to export it, the GNU ld linker complains that
//! it can't resolve the symbol so here's a local version that cures the
//! problem.
//!
//! \return Does not return.
//
//*****************************************************************************
void abort(void)
{
    while(1)
    {
    }
}

//*****************************************************************************
//
//! This is a lightweight substitute for the C runtime time() function.
//!
//! \param pTime is a pointer to storage for the returned time. If NULL, the
//! parameter is ignored.
//!
//! \note MatrixSSL uses time() purely to get the first 4 values of the
//! server random block. We don't have access to the real UTC time so just
//! return the second count since the system started instead. If your system
//! has a UTC reference, this function could be replaced with one that returns
//! the actual time.
//!
//! \return Returns the number of seconds since the system started the SSL
//! timer. The same value is also returned in *pTime if pTime is not NULL.
//
//*****************************************************************************
time_t
NoOSTime(time_t *pTime)
{
    unsigned long ulSeconds = g_ulSeconds;

    if(pTime)
    {
        *pTime = ulSeconds;
    }

    return(ulSeconds);
}

//*****************************************************************************
//
// Wrappers for C runtime memory management functions. We use the public domain
// bget library as our heap manager and wrap the standard C functions around
// its APIs.
//
//*****************************************************************************

//*****************************************************************************
//
//! Allocates a buffer of size bytes from the g_pcSSLHeap heap.
//!
//! \param size is the number of bytes to allocate from the heap.
//!
//! \return Returns a pointer to the allocated block or NULL if insufficient
//! space remains free in the heap.
//
//*****************************************************************************
void *ssl_mem_malloc(size_t size)
{
    void *pRet;

    pRet = bget((bufsize)size);

#ifdef DEBUG
    //
    // Query information on the current state of the heap.
    //
    bstats(&g_CurAlloc, &g_TotFree, &g_MaxFree, &g_MallocCount,
           &g_FreeCount);

    //
    // If we failed to allocate a block, remember the larges size we were being
    // asked for when the failure occurred.
    //
    if((pRet == NULL) && (size > g_OverCommit))
    {
        g_OverCommit = size;
    }

    //
    // Update our "minimum free memory" value
    //
    if(g_TotFree < g_MinFree)
    {
        g_MinFree = g_TotFree;
    }
#endif

    return(pRet);
}

//*****************************************************************************
//
//! Allocates a buffer suitable for an array from the g_pcSSLHeap heap.
//!
//! \param nelem is the number of array elements to allocate
//! \param elsize is the size in bytes of each array element.
//!
//! This function allocates a block of memory if size (nelem * elsize) bytes
//! and returns its pointer to the caller.
//!
//! \return Returns a pointer to the allocated block or NULL if insufficient
//! space remains free in the heap.
//
//*****************************************************************************
void *ssl_mem_calloc(size_t nelem, size_t elsize)
{
    void *pRet;

    pRet = bget((bufsize)(elsize * nelem));

#ifdef DEBUG
    //
    // Query information on the current state of the heap.
    //
    bstats(&g_CurAlloc, &g_TotFree, &g_MaxFree, &g_MallocCount,
           &g_FreeCount);

    //
    // Update our "minimum free memory" value
    //
    if(g_TotFree < g_MinFree)
    {
        g_MinFree = g_TotFree;
    }
#endif

    return(pRet);
}

//*****************************************************************************
//
//! Resizes an existing buffer allocation, maintaining the contents of the old
//! buffer in the newly allocated one.
//!
//! \param buf is a pointer to the existing buffer as returned by a previous
//! call to malloc or calloc.
//! \param size is the number of bytes to allocate from the heap.
//!
//! This function allocates a new block of size bytes and copies the contents
//! of the old allocation, buf, into the new block before freeing the old
//! allocation.
//!
//! \return Returns a pointer to the allocated block or NULL if insufficient
//! space remains free in the heap.
//
//*****************************************************************************
void *ssl_mem_realloc(void *buf, size_t size)
{
    void *pRet;

    pRet = bgetr(buf, (bufsize)size);

#ifdef DEBUG
    //
    // Query information on the current state of the heap.
    //
    bstats(&g_CurAlloc, &g_TotFree, &g_MaxFree, &g_MallocCount,
           &g_FreeCount);

    //
    // Update our "minimum free memory" value
    //
    if(g_TotFree < g_MinFree)
    {
        g_MinFree = g_TotFree;
    }
#endif

    return(pRet);
}


//*****************************************************************************
//
//! Frees a buffer from the g_pcSSLHeap heap.
//!
//! \param buf is a pointer to the buffer which is to be freed.
//!
//! This function frees an allocation from the g_pcSSLHeap heap. The pointer
//! passed must have been previously returned from a call to malloc, calloc or
//! realloc.
//!
//! \return None.
//
//*****************************************************************************
void ssl_mem_free(void *buf)
{
    brel(buf);

#ifdef DEBUG
    //
    // Query information on the current state of the heap.
    //
    bstats(&g_CurAlloc, &g_TotFree, &g_MaxFree, &g_MallocCount,
           &g_FreeCount);

    //
    // Update our "minimum free memory" value (though it is very unlikely that
    // freeing memory will cause the minimum free size to decrease!).
    //
    if(g_TotFree < g_MinFree)
    {
        g_MinFree = g_TotFree;
    }
#endif
}

//*****************************************************************************
//
//! Overrides the default timer selection used to provide system time to the
//! SSL library.
//!
//! \param ulTimerBase is the base address of the hardware timer that the OS
//! layer should use to provide a system tick to the SSL library.
//!
//! This function allows a client to chose which of the available hardware
//! timers should be used to provide the time reference for the SSL library.
//! By default, timer 0 is used.
//!
//! \note This call is only valid prior to sslOpenOsdep(). If called after this,
//! a debug build will throw an assert failure. The caller is responsible for
//! having installed the appropriate timer interrupt handler vector prior
//! to making this call.
//!
//! \Returns None.
//
//*****************************************************************************
void sslSetHardwareTimer(unsigned long ulTimerBase)
{
    //
    // This call is only valid prior to sslOpenOsdep when the timer is actually
    // claimed and initialized.
    //
    sslAssert(!g_bSslTimerInitialized);

    //
    // Ensure we were passed a valid timer base address.
    //
    sslAssert((ulTimerBase == TIMER0_BASE) || (ulTimerBase == TIMER1_BASE) ||
              (ulTimerBase == TIMER2_BASE) || (ulTimerBase == TIMER3_BASE));

    //
    // Remember which timer we have been told to use.
    //
    g_ulSslTimerBase = ulTimerBase;

    //
    // Given the timer base address, determine the equivalent SysCtl peripheral
    // identifier.
    //
    switch(ulTimerBase)
    {
        case TIMER0_BASE:
            g_ulSslTimerPeriph = SYSCTL_PERIPH_TIMER0;
            g_ulSslTimerInt = INT_TIMER0A;
            break;

        case TIMER1_BASE:
            g_ulSslTimerPeriph = SYSCTL_PERIPH_TIMER1;
            g_ulSslTimerInt = INT_TIMER1A;
            break;

        case TIMER2_BASE:
            g_ulSslTimerPeriph = SYSCTL_PERIPH_TIMER2;
            g_ulSslTimerInt = INT_TIMER2A;
            break;

        case TIMER3_BASE:
            g_ulSslTimerPeriph = SYSCTL_PERIPH_TIMER3;
            g_ulSslTimerInt = INT_TIMER3A;
            break;
    }
}

//*****************************************************************************
//
//! Initializes the OS support layer.
//!
//! \param None.
//!
//! This function is called during processing of martixSslOpen to initialize
//! the OS support on behalf of the SSL library. It sets up the heap used to
//! provide buffers to the module and initializes the hardware timer used to
//! generate a time reference.
//!
//! \note It is assumed that the caller will have enabled the relevant
//! timer using a call to SysCtlPeripheralEnable prior to making this
//! call. If this is not done, this function will generate a bus fault.
//!
//! \return Returns 0 on success or a negative number on failure.
//
//*****************************************************************************
int32 sslOpenOsdep(void)
{
    unsigned long ulUser0;
    unsigned long ulUser1;

    //
    // Initialize the block of memory to be used as a heap for the SSL library.
    //
    bpool(g_pcSSLHeap, MAX_SSL_HEAP_SIZE);

    //
    // Remember the system clock rate.
    //
    g_ulClockRate = SysCtlClockGet();

    //
    // Enable the timer we will be using to track system timer and reset it
    // to ensure that it is in a known idle state.
    //
    SysCtlPeripheralEnable(g_ulSslTimerPeriph);
    SysCtlPeripheralReset(g_ulSslTimerPeriph);

    //
    // Configure the timer. We set it up as a periodic, 32 bit counter
    // providing an interrupt once per second.
    //
    TimerConfigure(g_ulSslTimerBase, TIMER_CFG_32_BIT_PER);
    TimerLoadSet(g_ulSslTimerBase, TIMER_A, g_ulClockRate);
    IntEnable(g_ulSslTimerInt);
    TimerIntEnable(g_ulSslTimerBase, TIMER_TIMA_TIMEOUT);
    TimerEnable(g_ulSslTimerBase, TIMER_A);
    g_bSslTimerInitialized = true;

    //
    // Seed the "random" number generator with something that is board specific
    // like, for example, the MAC address. This is typically stored in the
    // flash user registers.
    //
    FlashUserGet(&ulUser0, &ulUser1);
    SeedRandom(ulUser0 ^ ulUser1);

    //
    // Tell the caller all is well.
    //
    return(0);
}

int32 sslCloseOsdep(void)
{
    //
    // Stop our timer and unregister its interrupt.
    //
    TimerDisable(g_ulSslTimerBase, TIMER_A);
    TimerIntDisable(g_ulSslTimerBase, TIMER_TIMA_TIMEOUT);
    TimerIntUnregister(g_ulSslTimerBase, TIMER_A);
    g_bSslTimerInitialized = false;

    //
    // Let the caller know everything went as planned.
    //
    return 0;
}

//*****************************************************************************
//
//! Fills the supplied buffer with random bytes.
//!
//! \param bytes is a pointer to the buffer into which random data is to be
//! written.
//! \param size is the number of bytes of random data to write to the supplied
//! buffer.
//!
//! This function generates random data for use by the SSL library. The
//! algorithm used here to generate the random data is a rather simple shift/
//! XOR process seeded with a number derived from the system's ethernet MAC
//! address. It should be pretty random but whether it is "cryptographically
//! random" or not is debatable. Unfortunately, I don't have any alpha particle
//! sources or cosmic ray counters around so this will have to do for now.
//!
//! \return Returns -1 on failure or the number of bytes of random data
//! written to buffer "bytes" if successful.
//
//*****************************************************************************
int32 sslGetEntropy(unsigned char *bytes, int32 size)
{
    int32 iLoop;
    unsigned long ulRand;

    for(iLoop = 0; iLoop < size; iLoop++)
    {
        //
        // Get 4 bytes of random data.
        //
        ulRand = GetRandom();

        //
        // Save one byte of the random unsigned long value into the output
        // buffer.
        //
        bytes[iLoop] = (unsigned char)(ulRand & 0xFF);
    }

    //
    // Tell the caller how many bytes of "random" data we generated.
    //
    return(size);
}

#ifdef DEBUG
void psBreak(void)
{
    ASSERT(0);
}
#endif

int32 sslInitMsecs(sslTime_t *t)
{
    unsigned long ulSeconds;
    unsigned long ulTimerVal1;
    unsigned long ulTimerVal2;
    unsigned long ulElapsedTicks;
    sslTime_t sTime;

    //
    // Read the timer value and take a snapshot of the wrap count. We
    // read the value twice to determine if there is a chance that we
    // wrapped during the process.
    //
    do
    {
        ulTimerVal1 = TimerValueGet(g_ulSslTimerBase, TIMER_A);
        ulSeconds = g_ulSeconds;
        ulTimerVal2 = TimerValueGet(g_ulSslTimerBase, TIMER_A);
    } while (ulTimerVal2 > ulTimerVal1);

    //
    // How many ticks have elapsed since the last interrupt?
    //
    ulElapsedTicks = g_ulClockRate - ulTimerVal2;

    //
    // We will typically be running the system clock at somewhere between 8MHz
    // and 50Mhz so g_ulClockRate/1000000 will be in the range 8 to 50 making
    // the following calculation overflow/underflow safe. Errors will be
    // introduced in the microsecond calculation if the clock rate is not an
    // integer number of MHz, however.
    //
    t->usec = ulElapsedTicks/(g_ulClockRate/1000000);
    t->sec = ulSeconds;

    //
    // This function returns the elapsed millisecond count since we started
    // so set up a zero time structure and return the millisecond difference
    // between this and our current time.
    //
    sTime.sec = 0;
    sTime.usec = 0;
    return(sslDiffMsecs(sTime, *t));
}

/*
    Return the delta in milliseconds between two time values
*/
long sslDiffMsecs(sslTime_t then, sslTime_t now)
{
    long lSeconds;
    long lExtraMilliseconds;

    //
    // Consider first the easiest case when the two times are within the
    // same second. This, of course, assimes that then and now are correctly
    // ordered with now later than then.
    //
    if(now.sec == then.sec)
    {
        return((now.usec - then.usec)/1000);
    }
    else
    {
        //
        // The times are in different seconds so consider the seconds and
        // microseconds separately.
        //
        lSeconds = (now.sec - then.sec) - 1;
        lExtraMilliseconds = ((1000000 - then.usec) + now.usec)/1000;

        //
        // Guard against overflow. If the time difference is too large to
        // hold in a long, send back the largest value allowable rather than
        // wrapping and sending something completely bogus.
        //
        if(lSeconds > (MAX_OVERFLOW_FREE_SECONDS - lExtraMilliseconds))
        {
            //
            // Calculation would overflow so return the largest different we
            // can represent in a single (signed) long.
            //
            return(0x7FFFFFFF);
        }
        else
        {
            //
            // No overflow worries so calculate the number of milliseconds
            // by multiplying seconds by 1000 and adding the extra bit.
            //
            return((lSeconds * 1000) + lExtraMilliseconds);
        }
    }
}

/*
    Return the delta in seconds between two time values
*/
int32 sslDiffSecs(sslTime_t then, sslTime_t now)
{
    int32 iSeconds;

    //
    // For a first approximation we just subtract the seconds portion of the
    // times provided. We assume the caller gets the order of then and now
    // correct. If not, they will receive a huge and unexpected difference
    // value.
    //
    iSeconds = now.sec - then.sec;

    //
    // Since we want to round to whole seconds, we need to take a look at the
    // microsecond portion and correct if required. 1.999 seconds to 2.000
    // seconds is distinctly less than 1 second, for example.
    //
    if(now.usec < then.usec)
    {
        iSeconds--;
    }

    return(iSeconds);
}

/*
    Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater
*/
int32    sslCompareTime(sslTime_t a, sslTime_t b)
{
    if((a.sec > b.sec) || ((a.sec == b.sec) && (a.usec > b.usec)))
    {
        return(0);
    }
    else
    {
        return(1);
    }
}
