/************************************************************************************
** File: - E:\ARM\lm3s8962projects\MatrixSSL\Source\SSL\Layer\Head\ssl_priv.h
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      ssl_priv.h - Private header defining types used by ssl.c
** 
** Version: 1.1
** Date created: 17:41:22,14/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

#ifndef _SSL_PRIV_H_
#define _SSL_PRIV_H_


//
// The SSL protocol control block.
//
struct ssl_pcb {
    //
    // TCP protocol control block for the underlying connection.
    //
    struct tcp_pcb *tpcb;

    //
    // Client-supplied value passed back on each callback.
    //
    void *pUserArg;

    //
    // MatrixSSL session state data.
    //
    ssl_t *pSsl;

    //
    // Buffer used to hold encoded data received from TCP but not yet
    // decoded.
    //
    sslBuf_t sSslEncodedBuff;

    //
    // Buffer used as the target for decoded data received via TCP.
    //
    sslBuf_t sSslInBuff;

    //
    // Buffer used to hold encoded data destined to be sent via TCP.
    //
    sslBuf_t sSslOutBuff;

    //
    // The number of bytes of encoded data in sSslOutBuff remaining to be
    // transmitted after the current transmission (if any) completes.
    //
    unsigned long ulOutCount;

    //
    // The number of bytes in the last packet sent to TCP for which we have not
    // yet had a "sent" callback.
    //
    unsigned long ulBytesPending;

    //
    // Set to true when the SSL handshake process has completed.
    //
    int bHandshakeComplete;

    //
    // Function to be called when more send buffer space is available.
    //
    err_t (* sent)(void *arg, struct ssl_pcb *pcb, u16_t space);

    //
    // Function to be called when (in-sequence) data has arrived.
    //
    err_t (* recv)(void *arg, struct ssl_pcb *pcb, unsigned char *p, int len);

    //
    // Function to call when a listener has been connected.
    //
    err_t (* accept)(void *arg, struct ssl_pcb *newpcb, err_t err);

    //
    // Function which is called periodically.
    //
    err_t (* poll)(void *arg, struct ssl_pcb *pcb);

    //
    // Function to be called whenever a fatal error occurs.
    //
    void (* errf)(void *arg, err_t err);
//##### INTERNAL_BEGIN #####

#ifdef DEBUG_TIMING
    //
    // Time at which the session request arrived (in 10mS ticks).
    //
    unsigned long ulAcceptTime;

    //
    // Time at which handshaking was complete.
    //
    unsigned long ulHandshakeTime;

    //
    // Total number of bytes of data encoded this session.
    //
    unsigned long ulEncodeCount;

    //
    // Total number of bytes of data decoded this session.
    //
    unsigned long ulDecodeCount;
#endif
//##### INTERNAL_END #####
};

#endif /* _SSL_PRIV_H_ */

