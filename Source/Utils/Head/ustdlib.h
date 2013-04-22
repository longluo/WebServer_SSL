/************************************************************************************
** File: - E:\ARM\lm3s8962projects\WebIO\Source\Utils\Head\ustdlib.h
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      ustdlib.h - Prototypes for simple standard library functions.
** 
** Version: 1.0
** Date created: 10:43:58,20/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#ifndef __USTDLIB_H__
#define __USTDLIB_H__

#include <stdarg.h>

//*****************************************************************************
//
// If building with a C++ compiler, make all of the definitions in this header
// have a C binding.
//
//*****************************************************************************
#ifdef __cplusplus
extern "C"
{
#endif

//*****************************************************************************
//
//! \addtogroup ustdlib_api
//! @{
//
//*****************************************************************************

//*****************************************************************************
//
//! A structure that contains the broken down date and time.
//
//*****************************************************************************
typedef struct
{
    //
    //! The number of years since 0 AD.
    //
    unsigned short usYear;

    //
    //! The month, where January is 0 and December is 11.
    //
    unsigned char ucMon;

    //
    //! The day of the month.
    //
    unsigned char ucMday;

    //
    //! The day of the week, where Sunday is 0 and Saturday is 6.
    //
    unsigned char ucWday;

    //
    //! The number of hours.
    //
    unsigned char ucHour;

    //
    //! The number of minutes.
    //
    unsigned char ucMin;

    //
    //! The number of seconds.
    //
    unsigned char ucSec;
}
tTime;

//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************

//*****************************************************************************
//
// Prototypes for the APIs.
//
//*****************************************************************************
extern int uvsnprintf(char *pcBuf, unsigned long ulSize, const char *pcString,
                      va_list vaArgP);
extern int usprintf(char *pcBuf, const char *pcString, ...);
extern int usnprintf(char *pcBuf, unsigned long ulSize, const char *pcString,
                     ...);
extern void ulocaltime(unsigned long ulTime, tTime *psTime);
extern unsigned long ustrtoul(const char *pcStr, const char **ppcStrRet,
                              int iBase);
extern char *ustrstr(const char *pcHaystack, const char *pcNeedle);
extern int ustrnicmp(const char *pcStr1, const char *pcStr2, int iCount);
extern int ustrcasecmp(const char *pcStr1, const char *pcStr2);

//*****************************************************************************
//
// Mark the end of the C bindings section for C++ compilers.
//
//*****************************************************************************
#ifdef __cplusplus
}
#endif

#endif /* __USTDLIB_H__ */

