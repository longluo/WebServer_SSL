/************************************************************************************
** File: - E:\ARM\lm3s8962projects\WebIO\Source\lwipConfig\locator.h
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      locator.h - Prototypes for the device locator server.
** 
** Version: 1.0
** Date created: 10:39:12,20/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#ifndef __LOCATOR_H__
#define __LOCATOR_H__

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
// Function prototypes.
//
//*****************************************************************************
extern void LocatorInit(void);
extern void LocatorBoardTypeSet(unsigned long ulType);
extern void LocatorBoardIDSet(unsigned long ulID);
extern void LocatorClientIPSet(unsigned long ulIP);
extern void LocatorMACAddrSet(unsigned char *pucMACArray);
extern void LocatorVersionSet(unsigned long ulVersion);
extern void LocatorAppTitleSet(const char *pcAppTitle);

//*****************************************************************************
//
// Mark the end of the C bindings section for C++ compilers.
//
//*****************************************************************************
#ifdef __cplusplus
}
#endif

#endif /* __LOCATOR_H__ */ 

