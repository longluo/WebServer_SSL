/************************************************************************************
** File: - Z:\work\code\github\WebServer_SSL\Source\WebServer\lmi_fs.c
** 
** Copyright (C) Long.Luo.
** 
** Description: 
**      lmi_fs.c - File System Processing for lwIP Web Server Apps.
** 
** Version: 1.2
** Date created: 23:36:59,28/04/2013
** Author: long.luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#include <string.h>
#include "hw_ssi.h"
#include "hw_memmap.h"
#include "hw_sysctl.h"
#include "hw_types.h"
#include "gpio.h"
#include "ssi.h"
#include "sysctl.h"
#include "lwiplib.h"
#include "fs.h"
#include "fsdata.h"
#include "fatfs/src/ff.h"
#include "fatfs/src/diskio.h"
#include "display.h"

//*****************************************************************************
//
// Include the file system data for this application.  This file is generated
// by the makefsdata script from lwIP, using the following command (all on one
// line):
//
//     perl ../../DriverLib/third_party/lwip-1.2.0/apps/httpd/makefsdata fs
//          lmi-fsdata.c
//
// If any changes are made to the static content of the web pages served by the
// application, this script must be used to regenerate fsdata-qs.c in order for
// those changes to be picked up by the web server.
//
//*****************************************************************************
#include "lmi-fsdata.c"

//*****************************************************************************
//
// The following are data structures used by FatFs.
//
//*****************************************************************************
static FATFS g_sFatFs;
static volatile tBoolean g_bFatFsEnabled = false;

//*****************************************************************************
//
// Enable the SSI Port for FatFs usage.
//
//*****************************************************************************
static void
fs_enable(unsigned long ulFrequency)
{
    //
    // Disable the SSI Port.
    //
    SSIDisable(SSI0_BASE);

    //
    // Reconfigure the SSI Port for Fat FS operation.
    //
    SSIConfigSetExpClk(SSI0_BASE, SysCtlClockGet(), SSI_FRF_MOTO_MODE_0,
                       SSI_MODE_MASTER, ulFrequency, 8);

    //
    // Eanble the SSI Port.
    //
    SSIEnable(SSI0_BASE);
}

//*****************************************************************************
//
// Initialize the file system.
//
//*****************************************************************************
void
fs_init(void)
{
    FRESULT fresult;
    DIR g_sDirObject;

    //
    // Initialze the flag to indicate that we are disabled.
    //
    g_bFatFsEnabled = false;

    //
    // Initialize and mount the Fat File System.
    //
    fresult = f_mount(0, &g_sFatFs);
    if(fresult != FR_OK)
    {
        return;
    }

    //
    // Open the root directory for access.
    //
    fresult = f_opendir(&g_sDirObject, "/");

    //
    // Flag and display which file system we are using.
    //
    DisplayEnable(1000000);
    DisplayStringDraw("Web Server Using", 18, 48, 15);
    if(fresult == FR_OK)
    {
        //
        // Indicate and display that we are using the SD file system.
        //
        g_bFatFsEnabled = true;
        DisplayStringDraw("SD File System", 24, 56, 15);
    }
    else
    {
        //
        // Indicate and display that we are using the internal file system.
        //
        g_bFatFsEnabled = false;
        DisplayStringDraw("Internal File System", 6, 56, 15);
    }
    DisplayDisable();
}

//*****************************************************************************
// File System tick handler.
//*****************************************************************************
void
fs_tick(unsigned long ulTickMS)
{
    static unsigned long ulTickCounter = 0;

    //
    // Check if the file system has been enabled yet.
    //
    if(!g_bFatFsEnabled)
    {
        return;
    }

    //
    // Increment the tick counter.
    //
    ulTickCounter += ulTickMS;

    //
    // Check to see if the FAT FS tick needs to run.
    //
    if(ulTickCounter >= 10)
    {
        ulTickCounter = 0;
        disk_timerproc();
    }
}

//*****************************************************************************
//
// Open a file and return a handle to the file, if found.  Otherwise,
// return NULL.
//
//*****************************************************************************
struct fs_file *
fs_open(char *name)
{
    const struct fsdata_file *ptTree;
    struct fs_file *ptFile = NULL;
    FIL *ptFatFile = NULL;
    FRESULT fresult = FR_OK;

    //
    // Allocate memory for the file system structure.
    //
    ptFile = mem_malloc(sizeof(struct fs_file));
    if(NULL == ptFile)
    {
        return(NULL);
    }

    //
    // Check to see if the Fat File System has been enabled.
    //
    if(g_bFatFsEnabled)
    {
        //
        // Ensure that the file system access to the SSI port is active.
        //
        fs_enable(400000);

        //
        // Allocate memory for the Fat File system handle.
        //
        ptFatFile = mem_malloc(sizeof(FIL));
        if(NULL == ptFatFile)
        {
            mem_free(ptFile);
            return(NULL);
        }

        //
        // Attempt to open the file on the Fat File System.
        //
        fresult = f_open(ptFatFile, name, FA_READ);
        if(FR_OK == fresult)
        {
            ptFile->data = NULL;
            ptFile->len = NULL;
            ptFile->index = NULL;
            ptFile->pextension = ptFatFile;
            return(ptFile);
        }

        //
        // If we get here, we failed to find the file on the Fat File System,
        // so free up the Fat File system handle/object.
        //
        mem_free(ptFatFile);
        mem_free(ptFile);
        return(NULL);
    }

    //
    // Initialize the file system tree pointer to the root of the linked list.
    //
    ptTree = FS_ROOT;

    //
    // Begin processing the linked list, looking for the requested file name.
    //
    while(NULL != ptTree)
    {
        //
        // Compare the requested file "name" to the file name in the
        // current node.
        //
        if(strncmp(name, (char *)ptTree->name, ptTree->len) == 0)
        {
            //
            // Fill in the data pointer and length values from the
            // linked list node.
            //
            ptFile->data = (char *)ptTree->data;
            ptFile->len = ptTree->len;

            //
            // For now, we setup the read index to the end of the file,
            // indicating that all data has been read.
            //
            ptFile->index = ptTree->len;

            //
            // We are not using any file system extensions in this
            // application, so set the pointer to NULL.
            //
            ptFile->pextension = NULL;

            //
            // Exit the loop and return the file system pointer.
            //
            break;
        }

        //
        // If we get here, we did not find the file at this node of the linked
        // list.  Get the next element in the list.
        //
        ptTree = ptTree->next;
    }

    //
    // If we didn't find the file, ptTee will be NULL.  Make sure we
    // return a NULL pointer if this happens.
    //
    if(NULL == ptTree)
    {
        mem_free(ptFile);
        ptFile = NULL;
    }

    //
    // Return the file system pointer.
    //
    return(ptFile);
}

//*****************************************************************************
//
// Close an opened file designated by the handle.
//
//*****************************************************************************
void
fs_close(struct fs_file *file)
{
    //
    // If a Fat file was opened, free its object.
    //
    if(file->pextension)
    {
        mem_free(file->pextension);
    }

    //
    // Free the main file system object.
    //
    mem_free(file);
}

//*****************************************************************************
//
// Read the next chunck of data from the file.  Return the count of data
// that was read.  Return 0 if no data is currently available.  Return
// a -1 if at the end of file.
//
//*****************************************************************************
int
fs_read(struct fs_file *file, char *buffer, int count)
{
    int iAvailable;

    //
    // Check to see if a Fat File was opened and process it.
    //
    if(file->pextension)
    {
        unsigned short usBytesRead;
        FRESULT fresult;

        //
        // Ensure that the file system access to the SSI port is active.
        //
        fs_enable(400000);

        //
        // Read the data.
        //
        fresult = f_read(file->pextension, buffer, count, &usBytesRead);
        if((fresult != FR_OK) || (usBytesRead == 0))
        {
            return(-1);
        }
        return((int)usBytesRead);
    }

    //
    // Check to see if more data is available.
    //
    if(file->len == file->index)
    {
        //
        // There is no remaining data.  Return a -1 for EOF indication.
        //
        return(-1);
    }

    //
    // Determine how much data we can copy.  The minimum of the 'count'
    // parameter or the available data in the file system buffer.
    //
    iAvailable = file->len - file->index;
    if(iAvailable > count)
    {
        iAvailable = count;
    }

    //
    // Copy the data.
    //
    memcpy(buffer, file->data + iAvailable, iAvailable);
    file->index += iAvailable;

    //
    // Return the count of data that we copied.
    //
    return(iAvailable);
}
