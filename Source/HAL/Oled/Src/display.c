//*****************************************************************************
//
// display.c - Wrapper functions for the simple display driver operations
//             used by the webserver_ssl application.
//
// Copyright (c) 2007-2008 Luminary Micro, Inc.  All rights reserved.
// 
// Software License Agreement
// 
// Luminary Micro, Inc. (LMI) is supplying this software for use solely and
// exclusively on LMI's microcontroller products.
// 
// The software is owned by LMI and/or its suppliers, and is protected under
// applicable copyright laws.  All rights are reserved.  You may not combine
// this software with "viral" open-source software in order to form a larger
// program.  Any use in violation of the foregoing restrictions may subject
// the user to criminal sanctions under applicable laws, as well as to civil
// liability for the breach of the terms and conditions of this license.
// 
// THIS SOFTWARE IS PROVIDED "AS IS".  NO WARRANTIES, WHETHER EXPRESS, IMPLIED
// OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE APPLY TO THIS SOFTWARE.
// LMI SHALL NOT, IN ANY CIRCUMSTANCES, BE LIABLE FOR SPECIAL, INCIDENTAL, OR
// CONSEQUENTIAL DAMAGES, FOR ANY REASON WHATSOEVER.
// 
// This is part of revision 226 of the Stellaris SSL Web Server.
//
//*****************************************************************************

#include "hw_memmap.h"
#include "hw_types.h"
#include "hw_ints.h"
#include "rit128x96x4.h"


//*****************************************************************************
//
// Different EK boards use different displays. We wrap the simple display
// functions used in the webserver application to keep as much code as possible
// common between different target boards.
//
//*****************************************************************************
extern void DisplayStringDraw(const char *pcStr,
                              unsigned long ulX,
                              unsigned long ulY,
                              unsigned char ucLevel)
{
    RIT128x96x4StringDraw(pcStr, ulX, ulY, ucLevel);
}

extern void DisplayInit(unsigned long ulFrequency)
{
    RIT128x96x4Init(ulFrequency);
}

extern void DisplayEnable(unsigned long ulFrequency)
{
    RIT128x96x4Enable(ulFrequency);
}

extern void DisplayDisable(void)
{
    RIT128x96x4Disable();
}

