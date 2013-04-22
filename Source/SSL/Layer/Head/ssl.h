/************************************************************************************
** File: - E:\ARM\lm3s8962projects\MatrixSSL\Source\SSL\Layer\Head\ssl.h
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      ssl.h - SSL layer above the lwIP TCP API. 
** 
** Version: 1.1
** Date created: 17:40:52,14/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#ifndef _SSL_H_
#define _SSL_H_


//*****************************************************************************
//
// Note: The interface defined here is intended to mirror the lwIP TCP 
//  interface allowing easy porting of other protocols on top of the matrixSSL
//  stack. The subset of APIs supported is based on the requirements of the 
//  existing lwip HTTPD implementation. Addition of any missing APIs required
//  to port additional layers above this is left as an exercise for the reader.
//
//*****************************************************************************
#include "lwiplib.h"


//*****************************************************************************
//
// Data type definitions.
//
//*****************************************************************************
struct ssl_pcb;

//*****************************************************************************
//
// Receive and transmit buffer sizes used for SSL sessions. 
//
//*****************************************************************************
#define SSL_RXBUFFER_SIZE 1024
#define SSL_TXBUFFER_SIZE 1024
#define SSL_ENCBUFFER_SIZE 1024

//*****************************************************************************
//
// Public API prototypes.
//
//*****************************************************************************
err_t ssl_init(void);
struct ssl_pcb *ssl_new(void);
err_t ssl_bind(struct ssl_pcb *pcb, struct ip_addr *ipaddr, u16_t port);
err_t ssl_listen(struct ssl_pcb *pcb);
void ssl_arg(struct ssl_pcb *pcb, void *arg);
void ssl_accept(struct ssl_pcb *pcb,
    err_t (* accept)(void *arg, struct ssl_pcb *newpcb, err_t err));
void ssl_recv(struct ssl_pcb *pcb,
    err_t (* recv)(void *arg, struct ssl_pcb *tpcb, unsigned char *p, int len));
void ssl_sent(struct ssl_pcb *pcb,
    err_t (* sent)(void *arg, struct ssl_pcb *tpcb, u16_t len));
void ssl_poll(struct ssl_pcb *pcb,
    err_t (* poll)(void *arg, struct ssl_pcb *tpcb));
void ssl_err(struct ssl_pcb *pcb, void (* err)(void *arg, err_t err));
void ssl_recved(struct ssl_pcb *pcb, u16_t len);
void ssl_abort(struct ssl_pcb *pcb);
err_t ssl_close(struct ssl_pcb *pcb);
err_t ssl_write(struct ssl_pcb *pcb, const void *dataptr, u16_t len);
void ssl_setprio(struct ssl_pcb *pcb, u8_t prio);
err_t ssl_output(struct ssl_pcb *pcb);
u16_t ssl_mss(struct ssl_pcb *pcb);
u16_t ssl_sndbuf(struct ssl_pcb *pcb);

#endif /* _SSL_H_ */

