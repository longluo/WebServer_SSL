/******************************************************************************
 *
 * webserver-ssl-ek-lm3s8962.ld - Scatter file for Sourcery G++
 *
 * Copyright (c) 2007 Luminary Micro, Inc.  All rights reserved.
 * Luminary Micro Confidential - For Use Under NDA Only
 *
 *****************************************************************************/

/******************************************************************************
 *
 * Define the end of the heap space, which determines the beginning of the
 * stack space.
 *
 *****************************************************************************/
__cs3_heap_end = __cs3_region_end_ram - 7072;

/******************************************************************************
 *
 * Define the interrupt handlers used by the application.
 *
 *****************************************************************************/
EXTERN(SysTickIntHandler)
__cs3_isr_systick = SysTickIntHandler;
EXTERN(SslTimerIntHandler)
__cs3_isr_timer0a = SslTimerIntHandler;
EXTERN(lwIPEthernetIntHandler)
__cs3_isr_ethernet0 = lwIPEthernetIntHandler;
