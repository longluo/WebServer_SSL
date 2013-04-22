/************************************************************************************
** File: - E:\ARM\lm3s8962projects\MatrixSSL\Source\SSL\Layer\Src\ssl.c
**  
** Copyright (C), Long.Luo, All Rights Reserved!
** 
** Description: 
**      ssl.c - An SSL layer above the lwIP TCP API.
** 
** Version: 1.2
** Date created: 17:40:19,14/04/2013
** Author: Long.Luo
** 
** --------------------------- Revision History: --------------------------------
** 	<author>	<data>			<desc>
** 
************************************************************************************/

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
#include "matrixSsl.h"
#include "ssl.h"
#include "ssl_priv.h"
#include <string.h>

#ifdef DEBUG
#include "uartstdio.h"

//*****************************************************************************
//
// For debug output, the client must have called UARTStdioInit prior
// to calling the SSL module API.
//
//*****************************************************************************

//*****************************************************************************
//
// DEBUG_MSG outputs a pritnf-style debug message on the UART in DEBUG builds.
//
//*****************************************************************************
#define DEBUG_MSG UARTprintf

#else

//*****************************************************************************
//
// In release builds, remove all debug messages.
//
//*****************************************************************************
#define DEBUG_MSG  while(0)((int (*)(char *, ...))0)

#endif

//##### INTERNAL_BEGIN #####
#ifdef DEBUG_TIMING
//*****************************************************************************
//
// Globals related to gathering performance data.
//
//*****************************************************************************
extern unsigned long g_ulSysTickCounter;
unsigned long g_ulSessionIndex = 0;
typedef struct
{
    unsigned long ulHandshakeTime;
    unsigned long ulActiveTime;
    unsigned long ulDecodeCount;
    unsigned long ulEncodeCount;
}
tSSLSessionStats;

#define MAX_SESSION_STATS 16

tSSLSessionStats g_sSessionStats[MAX_SESSION_STATS];

#endif

//##### INTERNAL_END #####
//*****************************************************************************
//
// Globals required by SSL library.
//
//*****************************************************************************
sslKeys_t *g_pSslKeys;
extern unsigned long g_ulPrivKeySrvLen;
extern unsigned long g_ulCertSrvLen;
extern unsigned char g_pcCertSrv[];
extern unsigned char g_pcPrivKeySrv[];

//*****************************************************************************
//
// Internal statistics and debug globals.
//
//*****************************************************************************
unsigned long g_ulSSLSessionCount = 0;
unsigned long g_ulMaxSSLSessions = 0;
unsigned long g_ulSSLSessionFailures = 0;
unsigned long g_ulAckCountError = 0;

//****************************************************************************
//
// Internal type definitions
//
//****************************************************************************
typedef struct
{
    unsigned char cError;
    char *pcDesc;
} tSslError;

typedef enum
{
    FALSE = 0,
    TRUE = 1
} tBool;

//****************************************************************************
//
// Error code lookup table
//
//****************************************************************************
tSslError g_sSslErrors[] =
{
    {SSL_ALERT_CLOSE_NOTIFY, "CLOSE_NOTIFY"},
    {SSL_ALERT_UNEXPECTED_MESSAGE, "UNEXPECTED_MESSAGE"},
    {SSL_ALERT_BAD_RECORD_MAC, "BAD_RECORD_MAC"},
    {SSL_ALERT_DECOMPRESSION_FAILURE, "DECOMPRESSION_FAILURE"},
    {SSL_ALERT_HANDSHAKE_FAILURE, "HANDSHAKE_FAILURE"},
    {SSL_ALERT_NO_CERTIFICATE, "NO_CERTIFICATE"},
    {SSL_ALERT_BAD_CERTIFICATE, "BAD_CERTIFICATE"},
    {SSL_ALERT_UNSUPPORTED_CERTIFICATE, "UNSUPPORTED_CERTIFICATE"},
    {SSL_ALERT_CERTIFICATE_REVOKED, "CERTIFICATE_REVOKED"},
    {SSL_ALERT_CERTIFICATE_EXPIRED, "CERTIFICATE_EXPIRED"},
    {SSL_ALERT_CERTIFICATE_UNKNOWN, "CERTIFICATE_UNKNOWN"},
    {SSL_ALERT_ILLEGAL_PARAMETER, "ILLEGAL_PARAMETER"}
};

//****************************************************************************
//
// Internal function prototypes
//
//****************************************************************************
err_t ssl_tcp_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
err_t ssl_tcp_recv(void *arg, struct tcp_pcb *newpcb, struct pbuf *p,
                   err_t err);
err_t ssl_tcp_poll(void *arg, struct tcp_pcb *newpcb);
void ssl_tcp_err(void *arg, err_t err);
err_t ssl_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

//****************************************************************************
//
// Internal functions
//
//****************************************************************************

static void
dump_ssl_error(unsigned char cError)
{
    int iLoop;

    //
    // Look for a matching error code in our table.
    //
    for(iLoop = 0; iLoop < sizeof(g_sSslErrors)/sizeof(tSslError); iLoop++)
    {
        if(g_sSslErrors[iLoop].cError == cError)
        {
            //
            // We found this error so dump the description to the debug log.
            //
            DEBUG_MSG("SSL error %d: %s\n", cError, g_sSslErrors[iLoop].pcDesc);
            return;
        }
    }

    //
    // This error was not in our table so dump a general message instead.
    //
    DEBUG_MSG("SSL error %d: UNKNOWN\n", cError);
}

//*****************************************************************************
//
//! Move any unused data in a buffer to the start of the buffer.
//!
//! \param pBuf is a pointer to the SSL buffer whose data is to be packed
//!
//! This function is called to move any unused data in the supplied buffer to
//! the beginning of that buffer, hence consolidating all free space into the
//! area above the buffer end pointer.
//!
//! \return None.
//
//*****************************************************************************
static void
tidy_buffer_data(sslBuf_t *pBuf)
{
    //
    // Is the data start pointer somewhere other than at the beginning of the
    // buffer?
    //
    if (pBuf->buf < pBuf->start)
    {
        //
        // Is the buffer empty?
        //
        if (pBuf->start == pBuf->end)
        {
            //
            // Yes - just move both the start and end pointers back to the
            // beginning of the buffer since there's no valid data there
            // anyway.
            //
            pBuf->end = pBuf->buf;
            pBuf->start = pBuf->buf;
        }
        else
        {
            //
            // No - there is unused data starting somewhere other than at the
            // beginning of the buffer so move the unused block back to the
            // beginning and fix up the start and end pointers accordingly.
            //
            DEBUG_MSG("Tidying buffer at 0x%08x. Moving data %d bytes\n",
                      pBuf->buf, (pBuf->end - pBuf->start));
            memmove(pBuf->buf, pBuf->start, pBuf->end - pBuf->start);
            pBuf->end -= (pBuf->start - pBuf->buf);
            pBuf->start = pBuf->buf;
        }
    }
}

//*****************************************************************************
//
//! Send SSL data to the remote host.
//!
//! \param pcb is the SSL protocol control block from which data is to be
//! sent.
//! \param bOutBuffer indicates which of the two pcb buffers contains the data
//! to be sent. Usually this will be set to true to indicate that the data is
//! in the output buffer. During initial handshaking, however, matrixSSL may
//! write outgoing data into the input buffer so we need to be able to source
//! data from there too.
//!
//! This function is called to send any pending data to the remote host. As
//! much data as can be sent in a single TCP transaction is sent with any
//! remaining data scheduled for transmission when the first transmission is
//! completed.
//!
//! \return Returns values as for tcp_write.
//
//*****************************************************************************
static err_t
send_data_to_tcp(struct ssl_pcb *pcb, tBool bOutBuffer)
{
    int iLenToWrite;
    err_t Error;
    unsigned char *pSendPtr;

    //
    // Determine the address of the first unsent byte in the output
    // buffer.
    //
    pSendPtr = pcb->sSslOutBuff.start + pcb->ulBytesPending;

    //
    // If we have been asked to send from the input buffer (as will happen
    // during handshaking), we copy the data into the output buffer and send
    // from there instead.
    //
    if(!bOutBuffer)
    {
        //
        // How much data do we have in the input buffer to send?
        //
        iLenToWrite = pcb->sSslInBuff.end - pcb->sSslInBuff.start;

        //
        // How much space is there in the output buffer?
        //
        if(iLenToWrite > (pcb->sSslOutBuff.size - (pcb->sSslOutBuff.end -
                          pSendPtr)))
        {
            //
            // Oops - there isn't enough space in the output buffer to send
            // what we have been asked to send!
            //
            DEBUG_MSG("Insufficient output buffer space. Have %d, need %d!\n",
                      pcb->sSslOutBuff.size -
                      (pcb->sSslOutBuff.end - pSendPtr), iLenToWrite);

            //
            // How should this case be handled? realloc the output buffer
            // dynamically or merely fail and tell the user to recompile
            // with a larger output buffer? For now, let's fail.
            //
            return(ERR_MEM);
        }
        else
        {
            //
            // Ensure that all valid data in the output buffer is at the start
            // of the buffer.
            //
            tidy_buffer_data(&pcb->sSslOutBuff);

            //
            // Copy the data we need to send from the input buffer to the output
            // buffer.
            //
            memcpy(pcb->sSslOutBuff.end,
                   pcb->sSslInBuff.start,
                   iLenToWrite);

            //
            // Fix up the buffer pointers to remove the data from the input
            // buffer and add it to the output buffer.
            //
            pcb->sSslOutBuff.end += iLenToWrite;
            pcb->sSslInBuff.start += iLenToWrite;

            //
            // Clean up the input buffer, moving remaining valid data to the
            // start.
            //
            tidy_buffer_data(&pcb->sSslInBuff);
        }
    }

    //
    // Recalculate the send address since we may have called tidy_buffer_data
    // above and this moves things around.
    //
    pSendPtr = pcb->sSslOutBuff.start + pcb->ulBytesPending;

    //
    // Ensure that we actually have something to send.
    //
    if(pcb->sSslOutBuff.end == pSendPtr)
    {
        //
        // Output buffer is empty so just return immediately.
        //
        DEBUG_MSG("No data on pcb 0x%08x\n", (unsigned long)pcb);
        return(ERR_OK);
    }

    //
    // We've got data to send. Send as much as we can right now and leave the
    // the rest until there is some space free.
    //
    iLenToWrite = min(tcp_sndbuf(pcb->tpcb),
                      (pcb->sSslOutBuff.end - pSendPtr));

    //
    // Fix up our buffer pointers to indicate what was sent and how much
    // data we have left to write. We do this before calling the TCP layer
    // since, if we do it afterwards, we could possibly (though unlikely)
    // hit a race condition where the ssl_tcp_sent callback is made before we
    // update the buffer status, resulting in data being sent multiple times.
    // This would not be a good thing.
    //
    // ulBytesPending tracks the number of bytes we have sent to TCP
    // but which have not yet been acknowledged.
    //
    pcb->ulBytesPending += (unsigned long)iLenToWrite;

    DEBUG_MSG("Writing %d bytes for pcb 0x%08x\n", iLenToWrite, pcb);

    //
    // Tell TCP to call us back when transmission is complete.
    //
    tcp_sent(pcb->tpcb, ssl_tcp_sent);

    //
    // Send the data to the TCP stack.
    //
    Error = tcp_write(pcb->tpcb, pSendPtr, iLenToWrite, 0);

    //
    // Tell the caller how we got on.
    //
    return(Error);
}

static void
ssl_free_connection(struct ssl_pcb *pcb)
{
    DEBUG_MSG("Freeing SSL pcb 0x%08x\n", pcb);

    //
    // Close the wrapped TCP control block. Note that we must set our callbacks
    // to NULL here to ensure that we don't get any more calls after we have
    // freed the SSL PCB memory!
    //
    if(pcb->tpcb)
    {
        tcp_sent(pcb->tpcb, NULL);
        tcp_recv(pcb->tpcb, NULL);
        tcp_err(pcb->tpcb, NULL);
        tcp_poll(pcb->tpcb, NULL, 4);
        tcp_arg(pcb->tpcb, NULL);
        tcp_close(pcb->tpcb);
    }

    //
    // Free the SSL encoded, tx and rx buffers if they exist.
    //
    if(pcb->sSslEncodedBuff.buf)
    {
        mem_free(pcb->sSslEncodedBuff.buf);
    }

    if(pcb->sSslInBuff.buf)
    {
        mem_free(pcb->sSslInBuff.buf);
    }

    if(pcb->sSslOutBuff.buf)
    {
        mem_free(pcb->sSslOutBuff.buf);
    }

    //
    // Close the SSL session if it exists.
    //
    if(pcb->pSsl)
    {
        matrixSslDeleteSession(pcb->pSsl);
    }

    //
    // Now free our SSL PCB
    //
    mem_free(pcb);

    //
    // Decrement our session counter.
    //
    g_ulSSLSessionCount--;
}

//*****************************************************************************
//
//! Callback from TCP indicating that data is available to be read.
//!
//! \param arg is the user data pointer provided to TCP via tcp_arg. This is
//! a pointer to our SSL PCB structure in this case.
//! \param tpcb is the TCP protocol control block for which this callback is
//! being made.
//! \param p is a pointer to a buffer object containing the data that has
//! been read. If this parameter is NULL, the remote host has closed the
//! connection.
//! \param err indicates any errors experienced in receiving the data.
//!
//! This function is called by TCP whenever a block of data is available to be
//! read. Assuming no error is reported, the received data is read, decoded
//! and passed up to the SSL client.
//!
//! Note that this function also handles cases where a decoded block of data
//! requires a response from the SSL layer. This is required to correctly
//! implement SSL handshaking, making the handshake process transparent to
//! the module clients.
//!
//! \return Returns values as for tcp_write. If no error is detected, ERR_OK
//! is returned. A negative value indicates an error. Valid values can be found
//! in the lwIP header file err.h.
//
//*****************************************************************************
err_t
ssl_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct ssl_pcb *pcb = (struct ssl_pcb *)arg;
    struct pbuf *q;
    err_t Error;
    int iRet;
    int iNewSize;
    int iDataCount;
    unsigned char cError;
    unsigned char cLevel;
    unsigned char cDesc;
    tBool bDone;

    DEBUG_MSG("ssl_tcp_recv pcb 0x%08x, pbuf 0x%08x, err %d\n", arg, p, err);

    //
    // If we have been passed a NULL pointer, this indicates that the remote
    // host closed the connection. Inform the client (which we expect to call
    // ssl_close to tidy up.
    //
    if(p == NULL)
    {
        DEBUG_MSG("Connection closed by remote host.\n");

        //
        // If a callback is registered, call it. Don't free the session
        // resources here since we expect the client to call ssl_close in
        // response to this callback.
        //
        if(pcb->recv)
        {
            DEBUG_MSG("Making client callback...\n");
            Error = (pcb->recv)(pcb->pUserArg, pcb, NULL, 0);
            return(Error);
        }
        else
        {
            //
            // If no callback is registered, we need to tidy up ourselves.
            //
            DEBUG_MSG("Freeing on NULL pcb.\n");
            ssl_free_connection(pcb);
            return(ERR_CLSD);
        }
    }


    //
    // If TCP is reporting an error so close our connection and return the error
    // we were passed.
    //
    if(err != ERR_OK)
    {
        DEBUG_MSG("Freeing on error.\n");
        pbuf_free(p);
        ssl_free_connection(pcb);
        return(err);
    }

    //
    // At this point, we can be sure that we have data to process.
    //

    //
    // Copy the received data into our incoming encoded data buffer, shuffling
    // any existing data in the buffer to the front first.
    //
    tidy_buffer_data(&pcb->sSslEncodedBuff);

    //
    // Make sure we have space to copy the new data into the buffer.
    //
    if(p->tot_len > pcb->sSslEncodedBuff.size - (pcb->sSslEncodedBuff.end -
                                                 pcb->sSslEncodedBuff.start))
    {
        //
        // Oops - our buffer is too small! Try to reallocate the encoded data
        // buffer. Set the buffer size to the minimum required to hold the
        // current data plus the new buffer just received.
        //
        iDataCount = pcb->sSslEncodedBuff.end - pcb->sSslEncodedBuff.start;
        iNewSize = iDataCount + p->tot_len;

        DEBUG_MSG("Encoded buffer too small! Reallocating to %d bytes\n",
                  iNewSize);

        pcb->sSslEncodedBuff.buf = mem_realloc(pcb->sSslEncodedBuff.buf,
                                               iNewSize);

        if(pcb->sSslEncodedBuff.buf == NULL)
        {
            DEBUG_MSG("Out of memory reallocing enc buf to %d bytes!\n",
                      iNewSize);
            ssl_free_connection(pcb);
            return(ERR_CLSD);
        }
        else
        {
            //
            // Fix up the buffer to preserve the existing data before we add
            // the new data to it.
            //
            pcb->sSslEncodedBuff.start = pcb->sSslEncodedBuff.buf;
            pcb->sSslEncodedBuff.size = iNewSize;
            pcb->sSslEncodedBuff.end = pcb->sSslEncodedBuff.start + iDataCount;
        }
    }

    //
    // Now copy the packet into our encoded buffer since we know we have
    // sufficient space. Note that we may have been passed a chain of pbufs
    // so we need to handle this case.
    //
    q = p;
    while(q)
    {
        memcpy(pcb->sSslEncodedBuff.end, q->payload, q->len);
        pcb->sSslEncodedBuff.end += q->len;
        q = q->next;
    }

    //
    // Tell TCP we received the data.
    //
    tcp_recved(pcb->tpcb, p->tot_len);

    //
    // Free the PCB (chain) since we no longer need it.
    //
    pbuf_free(p);

    //
    // Decode as much as we can into our receive buffer. Note the act of
    // decoding can result in either data being decoded for the client
    // application or a reply being constructed that we will need to
    // send to the remote host.
    //
    bDone = FALSE;

    while(!bDone)
    {
        DEBUG_MSG("Decoding %d bytes...\n", (pcb->sSslEncodedBuff.end -
                                             pcb->sSslEncodedBuff.start));
        iRet = matrixSslDecode(pcb->pSsl, &pcb->sSslEncodedBuff,
                               &pcb->sSslInBuff, &cError, &cLevel, &cDesc);

        //
        // Look at the SSL return code to determine what we need to do next.
        //
        switch(iRet)
        {
            //
            // SSL_SUCCESS indicates successful decode with no response
            // required and no data to pass to the layer above. Check to see
            // if handshaking is complete and, if so, notify the layer above.
            // If not, just return.
            //
            case SSL_SUCCESS:
                DEBUG_MSG("SSL_SUCCESS\n");

                //
                // Have we finished the handshake sequence?
                //
                if(matrixSslHandshakeIsComplete(pcb->pSsl))
                {
                    //
                    // Were we previously in the middle of handshaking?
                    //
                    if(pcb->bHandshakeComplete == FALSE)
                    {
                        //
                        // Yes - we need to let the client know that a new
                        // connection has been created (assuming they
                        // registered a callback).
                        //
                        DEBUG_MSG("Handshake complete.\n");
                        pcb->bHandshakeComplete = TRUE;
                        if(pcb->accept)
                        {
                            DEBUG_MSG("Making client callback.\n");
                            Error = (pcb->accept)(pcb->pUserArg, pcb, ERR_OK);
                        }
                    }
                    else
                    {
                        DEBUG_MSG("Handshake previously completed.\n");
                    }
                }

                //
                // Check to see if any more data remains to be processed. If
                // we do, go round again and decode it.
                //
                bDone = (pcb->sSslEncodedBuff.end ==
                         pcb->sSslEncodedBuff.start) ? TRUE : FALSE;

                break;

            //
            // SSL_SEND_RESPONSE indicates that a response needs to be sent to
            // the remote host. This will have been placed in the output
            // buffer. We need to send this immediately then wait for more
            // data.
            //
            case SSL_SEND_RESPONSE:
                DEBUG_MSG("SSL_SEND_RESPONSE\n");
                Error = send_data_to_tcp(pcb, FALSE);
                bDone = TRUE;
                break;

            //
            // SSL_ERROR indicated either an error decoding the data or
            // encoding a response. We try to send anything that had been
            // generated prior to the error then close the connection.
            //
            case SSL_ERROR:
                DEBUG_MSG("SSL_ERROR\n");
                dump_ssl_error(cError);
                if(pcb->sSslInBuff.end != pcb->sSslInBuff.start)
                {
                    send_data_to_tcp(pcb, FALSE);
                }
                ssl_free_connection(pcb);
                return(ERR_BUF);

            case SSL_ALERT:
                DEBUG_MSG("SSL_ALERT\n");
                break;

            case SSL_PARTIAL:
                DEBUG_MSG("SSL_PARTIAL\n");

                //
                // This return code indicates that the encoded buffer doesn't
                // contain a full record and that we need to wait for more
                // data. In this case, we just return and wait for the next
                // TCP packet to arrive.
                //
                bDone = TRUE;
                break;

            //
            // SSL_FULL indicates that there is insufficient space in the
            // output buffer to store the decoded message. Here we try to
            // reallocate the buffer then decode the data again.
            //
            case SSL_FULL:
                DEBUG_MSG("SSL_FULL\n");

                //
                // Tidy up the receive buffer.
                //
                tidy_buffer_data(&pcb->sSslInBuff);

                //
                // How much data exists in the buffer already?
                //
                iDataCount = pcb->sSslInBuff.end - pcb->sSslInBuff.start;

                //
                // Reallocate the buffer to something larger
                //
                pcb->sSslInBuff.size += SSL_TXBUFFER_SIZE;
                pcb->sSslInBuff.buf = mem_realloc(pcb->sSslInBuff.buf,
                                                  pcb->sSslInBuff.size);

                if(pcb->sSslInBuff.buf == NULL)
                {
                    //
                    // There is no memory available to allocate a larger buffer!
                    //
                    DEBUG_MSG("Can't realloc rx buffer to %d bytes!\n",
                              pcb->sSslInBuff.size);
                    ssl_free_connection(pcb);
                    return(ERR_MEM);
                }
                else
                {
                    //
                    // We managed to reallocate the buffer so fix up the buffer
                    // pointers.
                    //
                    DEBUG_MSG("Reallocated rx buffer to %d bytes\n",
                              pcb->sSslInBuff.size);
                    pcb->sSslInBuff.start = pcb->sSslInBuff.buf;
                    pcb->sSslInBuff.end = pcb->sSslInBuff.buf + iDataCount;
                }

                //
                // We've reallocated the receive buffer so go round and try to
                // decode again.
                //
                bDone = FALSE;
                break;

            //
            // SSL_PROCESS_DATA indicates that we have data to send to the
            // layer above. Go ahead and pass it on.
            //
            case SSL_PROCESS_DATA:
                DEBUG_MSG("SSL_PROCESS_DATA\n");

                //
                // We know that the handshake is now complete. If it just
                // completed, send an attach callback to the client.
                //
                if(pcb->bHandshakeComplete == 0)
                {
                    DEBUG_MSG("Handshake complete\n");
                    pcb->bHandshakeComplete = 1;
                    if(pcb->accept)
                    {
                        DEBUG_MSG("Notifying client accept\n");
                        Error = (pcb->accept)(pcb->pUserArg, pcb, ERR_OK);
                    }
                }

                //
                // Send any data we decoded back to the client.
                //
                if(pcb->recv &&
                   (pcb->sSslInBuff.end != pcb->sSslInBuff.start))
                {
                    Error = (pcb->recv)(pcb->pUserArg, pcb,
                                        pcb->sSslInBuff.start,
                                        (int)(pcb->sSslInBuff.end -
                                              pcb->sSslInBuff.start));
                }

                //
                // Exit the decode loop since we are done.
                //
                bDone = TRUE;
                break;

            default:
                //
                // We got an unrecognised error code from SSL. Close the
                // connection.
                //
                DEBUG_MSG("Unknown SSL error %d! Closing.\n", iRet);
                ssl_free_connection(pcb);
                return(ERR_CLSD);
        }
    }

    return(ERR_OK);
}

//*****************************************************************************
//
//! Callback from TCP indicating successful transmission of data.
//!
//! \param arg is the user data pointer provided to TCP via tcp_arg. This is
//! a pointer to our SSL PCB structure in this case.
//! \param tpcb is the TCP protocol control block for which this callback is
//! being made.
//! \param len is the length of data that was successfully acknowledged by
//! the remote host.
//!
//! This function is called by TCP whenever a block of data transmitted to the
//! remote host is acknowledged. When this occurs, we attempt to send any
//! remaining data destined for transmission.
//! When all data have been transmitted and acknowleged, we call back to the
//! SSL layer client informing it that the transmission is complete.
//!
//! \return Returns values as for tcp_write. If no error is detected, ERR_OK
//! is returned. A negative value indicates an error. Valid values can be found
//! in the lwIP header file err.h.
//
//*****************************************************************************
err_t
ssl_tcp_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    struct ssl_pcb *pcb = (struct ssl_pcb *)arg;
    err_t Error;

    DEBUG_MSG("ssl_tcp_sent for pcb 0x%08x, len %d\n", pcb, len);

    if(len > pcb->ulBytesPending)
    {
        //
        // This is odd. We've had more data acknowledged than we currently
        // expect to be acknowledged. Flag this as an error and set all our
        // unacknowledged block as acknowledged regardless of the length
        // worry.
        //
        // It may be more correct to report an error and close the
        // connection in this case.
        //
        DEBUG_MSG("%d acknowledged but we only expect %d!\n", len,
                  pcb->ulBytesPending);

        //
        // Set len to the maximum we expect and continue.
        //
        len = pcb->ulBytesPending;

        //
        // Update a counter indicating how often this situation arose.
        //
        g_ulAckCountError++;
    }

    //
    // Update our output buffer start pointer and counters now that we
    // know data has been sent.
    //
    DEBUG_MSG("Removing %d bytes from tx buffer\n", len);
    pcb->sSslOutBuff.start += len;
    pcb->ulBytesPending -= len;

    //
    // Determine the number of bytes in the buffer that have not yet been
    // passed to TCP.
    //
    pcb->ulOutCount = pcb->sSslOutBuff.end -
                      (pcb->sSslOutBuff.start + pcb->ulBytesPending);

    //
    // Determine whether we have remaining data to send on this connection
    // that we have not already passed to TCP.
    //
    if(pcb->ulOutCount != 0)
    {
        DEBUG_MSG("%d to send\n", pcb->ulOutCount);

        //
        // We do. Send the remaining data (or as much of it as we can).
        //
        Error = send_data_to_tcp(pcb, TRUE);

        if(Error != ERR_OK)
        {
            //
            // Something went wrong while trying to send the data.
            //
            DEBUG_MSG("Error %d sending data to TCP for pcb 0x%08x\n",
                      Error, pcb);
        }

        //
        // Don't make the callback to the SSL client at this point since the
        // buffer still contains data to be sent. Wait for the next callback
        // from TCP.
        //
    }
    else
    {
        //
        // Make the user callback if one is configured and we just finished
        // sending a block of SSL data.
        //
        if((pcb->ulOutCount == 0) && pcb->sent)
        {
            Error = (pcb->sent)(pcb->pUserArg, pcb, len);
        }
        else
        {
            Error = ERR_OK;
        }
    }

    return(Error);
}

err_t
ssl_tcp_poll(void *arg, struct tcp_pcb *newpcb)
{
    struct ssl_pcb *pcb = (struct ssl_pcb *)arg;
    err_t Error;

    DEBUG_MSG("ssl_tcp_poll\n");

    //
    // If the user has registered a callback, call it.
    //
    if(pcb->poll)
    {
        Error = (pcb->poll)(pcb->pUserArg, pcb);
    }
    else
    {
        Error = ERR_OK;
    }

    return(Error);
}

void
ssl_tcp_err(void *arg, err_t err)
{
    struct ssl_pcb *pcb = (struct ssl_pcb *)arg;

    DEBUG_MSG("ssl_tcp_err\n");

    //
    // If the user has registered a callback, call it.
    //
    if(pcb->errf)
    {
        (pcb->errf)(pcb->pUserArg, err);
    }
}

err_t
ssl_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    struct ssl_pcb *pNew;
    struct ssl_pcb *pListen = (struct ssl_pcb *)arg;
    int iRet;

    DEBUG_MSG("ssl_tcp_accept from listen pcb 0x%08x, err %d\n",
              (unsigned long)arg, err);

    //
    // Unless everything is OK, return immediately indicating a problem.
    //
    if(err != ERR_OK)
    {
        return(ERR_ABRT);
    }

    //
    // Grab some memory for our new protocol control block
    //
    pNew = mem_malloc(sizeof(struct ssl_pcb));

    //
    // Assuming we got the memory without problems...
    //
    if(!pNew)
    {
        DEBUG_MSG("Can't get new SSL PCB!\n");
        g_ulSSLSessionFailures++;
        return(ERR_MEM);
    }
    else
    {
        DEBUG_MSG("Allocated SSL PCB 0x%08x\n", (unsigned long)pNew);
    }

    //
    // Clear out our new SSL structure
    //
    memset(pNew, 0, sizeof(struct ssl_pcb));

    //
    // Associate the new TCP connection with this SSL PCB.
    //
    pNew->tpcb = newpcb;

    //
    // Copy the client's accept callback into the new PCB so that we have
    // access to it later when we need it
    //
    pNew->accept = pListen->accept;

    //
    // Increment our session counter. We do this here since the counter is
    // decremented inside ssl_free_connection and all failing cases from this
    // point onwards tidy up using this function (and will, hence, correctly undo
    // the counter increase we are about to do).
    //
    g_ulSSLSessionCount++;

    //
    // Create a new SSL session
    //
    iRet = matrixSslNewSession(&pNew->pSsl, g_pSslKeys, NULL, SSL_FLAGS_SERVER);
    if(iRet == 0)
    {
        DEBUG_MSG("New SSL session 0x%08x for PCB 0x%08x\n", pNew->pSsl, pNew);
    }
    else
    {
        //
        // Something went wrong and we can't create a new SSL session. Clean
        // up and close the incoming TCP connection too.
        //
        DEBUG_MSG("Error %d creating SSL session for PCB 0x%08x\n", iRet, pNew);
        ssl_free_connection(pNew);
        g_ulSSLSessionFailures++;
        return(ERR_MEM);
    }

    //
    // Allocate the 3 buffers we need for incoming and outgoing data.
    //
    pNew->sSslInBuff.buf = mem_malloc(SSL_RXBUFFER_SIZE);
    pNew->sSslOutBuff.buf = mem_malloc(SSL_TXBUFFER_SIZE);
    pNew->sSslEncodedBuff.buf = mem_malloc(SSL_ENCBUFFER_SIZE);

    //
    // Make sure allocated the buffers successfully.
    //
    if(!pNew->sSslOutBuff.buf || !pNew->sSslInBuff.buf ||
       !pNew->sSslEncodedBuff.buf)
    {
        DEBUG_MSG("Can't allocate SSL buffer memory!\n");
        ssl_free_connection(pNew);
        g_ulSSLSessionFailures++;
        return(ERR_MEM);
    }

    //
    // Set the initial buffer start and end values to indicate that the buffers
    // are empty.
    //
    pNew->sSslInBuff.start = pNew->sSslInBuff.buf;
    pNew->sSslInBuff.end = pNew->sSslInBuff.buf;
    pNew->sSslInBuff.size = SSL_RXBUFFER_SIZE;

    pNew->sSslOutBuff.start = pNew->sSslOutBuff.buf;
    pNew->sSslOutBuff.end = pNew->sSslOutBuff.buf;
    pNew->sSslOutBuff.size = SSL_TXBUFFER_SIZE;

    pNew->sSslEncodedBuff.start = pNew->sSslEncodedBuff.buf;
    pNew->sSslEncodedBuff.end = pNew->sSslEncodedBuff.buf;
    pNew->sSslEncodedBuff.size = SSL_ENCBUFFER_SIZE;

    //
    // Ensure that TCP passes us a pointer to our SSL PCB with all callbacks.
    //
    tcp_arg(pNew->tpcb, (void *)pNew);

    //
    // Register our internal callbacks with the new TCP PCB.
    //
    tcp_setprio(pNew->tpcb, TCP_PRIO_MIN);
    tcp_recv(pNew->tpcb, ssl_tcp_recv);
    tcp_err(pNew->tpcb, ssl_tcp_err);
    tcp_poll(pNew->tpcb, ssl_tcp_poll, 4);

    //
    // Now that the session has been successfully created, check to see if we now
    // have more sessions open than we have seen in the past and, if so, bump our
    // max session counter.
    //
    if(g_ulSSLSessionCount > g_ulMaxSSLSessions)
    {
        g_ulMaxSSLSessions = g_ulSSLSessionCount;
    }

    //
    // We don't make any callback to our client until after the SSL handshake
    // process has completed. All we do here is sit back and wait for the
    // remote host to send is the client hello which should spark off the
    // handshake exchange.
    //
    return(ERR_OK);
}

//****************************************************************************
//
// Public API functions
//
//****************************************************************************
err_t
ssl_init(void)
{
    int iRet;

    DEBUG_MSG("ssl_init\n");

    //
    // Initialize the SSL library.
    //
    iRet = matrixSslOpen();
    if(iRet < 0)
    {
        //
        // Something went wrong so kill the application with an error code.
        //
        return(ERR_IF);
    }

    //
    // Read the required certificates from memory.
    //
    iRet = matrixSslReadKeysMem(&g_pSslKeys, g_pcCertSrv, g_ulCertSrvLen,
                                g_pcPrivKeySrv, g_ulPrivKeySrvLen, NULL, 0);
    if(iRet < 0)
    {
        //
        // Something went wrong so kill the application with an error code.
        //
        return(ERR_MEM);
    }

    return(ERR_OK);
}

struct ssl_pcb *
ssl_new(void)
{
    struct ssl_pcb *pNew;

    DEBUG_MSG("ssl_new\n");

    //
    // Grab some memory for our protocol control block
    //
    pNew = mem_malloc(sizeof(struct ssl_pcb));

    //
    // Assuming we got the memory without problems...
    //
    if(pNew)
    {
        DEBUG_MSG("Allocated SSL PCB 0x%08x\n", (unsigned long)pNew);

        //
        // Clear out our new SSL structure
        //
        memset(pNew, 0, sizeof(struct ssl_pcb));

        //
        // Create a new TCP PCB that we will wrap with our SSL one.
        //
        pNew->tpcb = tcp_new();

        //
        // If the TCP creation failed, clean up.
        //
        if(!pNew->tpcb)
        {
            DEBUG_MSG("Can't get TCP PCB\n");
            DEBUG_MSG("Freed SSL PCB 0x%08x\n", (unsigned long)pNew);
            mem_free(pNew);
            pNew = NULL;
        }

        //
        // Tell TCP to pass us our own PCB pointer with all callbacks
        //
        tcp_arg(pNew->tpcb, (void *)pNew);
    }

    //
    // Pass our pointer back to the caller.
    //
    return(pNew);
}

err_t
ssl_close(struct ssl_pcb *pcb)
{
    err_t Error;
    int iRet;

    DEBUG_MSG("ssl_close 0x%08x\n", pcb);

    //
    // Send a closure alert to the remote host.
    //
    iRet = matrixSslEncodeClosureAlert(pcb->pSsl, &pcb->sSslOutBuff);
    switch(iRet)
    {
        //
        // We encoded the closure alert successfully.
        //
        case 0:
            //
            // Send the encoded closure alert.
            //
            Error = send_data_to_tcp(pcb, TRUE);

            //
            // If we got an error, dump a debug message. It is possible that
            // we are being asked to close the session in response to an
            // unexpected closure of the connection by the remote host and, in
            // this case, we would expect not to be able to send the data.
            //
            if(Error != ERR_OK)
            {
                DEBUG_MSG("Error %d from send_data_to_tcp!\n", Error);
            }
            break;

        //
        // The output buffer was too small.
        //
        case SSL_FULL:
            DEBUG_MSG("SSL_FULL on Closure Alert!\n");
            Error = ERR_MEM;
            break;

        //
        // Some other error occurred.
        //
        default:
            DEBUG_MSG("Error %d on Closure Alert!\n", iRet);
            Error = ERR_MEM;
            break;
    }

    //
    // If all went well, we probably sent a closure alert just prior to
    // this. If that's the case, the TCP stack may not actually have
    // transmitted the data yet so freeing the output buffer is probably not
    // the cleverest thing to do here. We should really either copy the output
    // data to a new buffer before sending it or wait for the send to complete
    // before freeing it.
    //

    //
    // Free all resources associated with this connection.
    //
    ssl_free_connection(pcb);

    return(Error);
}

//*****************************************************************************
//
//! Instructs the SSL module to bind a PCB to a local IP address and port.
//!
//! \param pcb is the SSL protocol control block which should be set to
//! listen for incoming connections.
//! \param ip_addr is the local IP address to bind the PCB to. IP_ADDR_ANY may
//! be specified in this parameter to bind to all local IP addresses.
//! \param port identifies the port to bind the PCB to.
//!
//! This function instructs the SSL module to wait for incoming TCP connections
//! using the supplied PCB. When an incoming connection is made, the client
//! will be notified via a callback to the function registered using API
//! ssl_accept().
//!
//! \return Returns ERR_OK if successful, ERR_MEM if insufficient memory
//! exists to satisfy the request or ERR_USE if another PCB is already bound to
//! the same port.
//
//*****************************************************************************
err_t
ssl_bind(struct ssl_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
    DEBUG_MSG("ssl_bind 0x%08x\n", (unsigned long)pcb);

    return(tcp_bind(pcb->tpcb, ipaddr, port));
}

//*****************************************************************************
//
//! Instructs the SSL module to listen for incoming connections.
//!
//! \param pcb is the SSL protocol control block which should be set to
//! listen for incoming connections.
//!
//! This function instructs the SSL module to wait for incoming TCP connections
//! using the supplied PCB. When an incoming connection is made, the client
//! will be notified via a callback to the function registered using API
//! ssl_accept().
//!
//! \return Returns ERR_OK if successful or ERR_MEM of insufficient
//! memory exists to satisfy the request.
//
//*****************************************************************************
err_t
ssl_listen(struct ssl_pcb *pcb)
{
    struct tcp_pcb *tpcb;

    DEBUG_MSG("ssl_listen 0x%08x\n", (unsigned long)pcb);

    tpcb = tcp_listen(pcb->tpcb);

    if(tpcb == NULL)
    {
        return(ERR_MEM);
    }

    pcb->tpcb = tpcb;

    //
    // Ask TCP to call our accept function as and when someone tries to talk
    // to us.
    //
    tcp_accept(pcb->tpcb, ssl_tcp_accept);

    return(ERR_OK);
}

//*****************************************************************************
//
//! Sets a user-specified callback data pointer.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the user callback data value is being set.
//! \param arg is a pointer which will be passed back to the client alongside
//! all future callbacks related to the supplied PCB.
//!
//! This function is called by the client application to register a client-
//! defined pointer which will be passed back with all future callbacks. A
//! client may use this to associate its own instance data with an SSL PCB and
//! aid in looking up state information when a callback is received.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_arg(struct ssl_pcb *pcb, void *arg)
{
    DEBUG_MSG("ssl_arg 0x%08x\n", (unsigned long)pcb);

    pcb->pUserArg = arg;
}

//*****************************************************************************
//
//! Sets a callback function pointer which will be called when a new connection
//! is made on a listening PCB.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the callback is being set.
//! \param accept is a pointer to a function which will be called when a new
//! incoming connection is made.
//!
//! This function is called by the client application to register a callback
//! which will be called whenever an incoming connection is successfully made.
//! The callback indicates that all SSL handshaking has completed successfully
//! and that data transfer may begin.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_accept(struct ssl_pcb *pcb,
    err_t (* accept)(void *arg, struct ssl_pcb *newpcb, err_t err))
{
    DEBUG_MSG("ssl_accept 0x%08x\n", (unsigned long)pcb);

    pcb->accept = accept;
}

//*****************************************************************************
//
//! Sets a callback function pointer that will be called when new data has
//! been received.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the callback is being set.
//! \param recv is a pointer to a function which will be called whenever new
//! data is received from the remote host and is available to be read.
//!
//! This function is called by the client application to register a callback
//! which will be called whenever newly received data is available to be read
//! by the client.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_recv(struct ssl_pcb *pcb,
    err_t (* recv)(void *arg, struct ssl_pcb *tpcb, unsigned char *p, int len))
{
    DEBUG_MSG("ssl_recv 0x%08x\n", (unsigned long)pcb);

    pcb->recv = recv;
}

//*****************************************************************************
//
//! Sets a callback function pointer which will be called when data has been
//! successfully transmitted.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the callback is being set.
//! \param sent is a pointer to a function which will be called when data has
//! been transmitted and acknowledged by the remote host.
//!
//! This function is called by the client application to register a callback
//! which will be called as transmitted data is acknowledged by the remote
//! host.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_sent(struct ssl_pcb *pcb,
    err_t (* sent)(void *arg, struct ssl_pcb *tpcb, u16_t len))
{
    DEBUG_MSG("ssl_sent 0x%08x\n", (unsigned long)pcb);

    pcb->sent = sent;
}

//*****************************************************************************
//
//! Sets a poll callback function pointer.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the callback is being set.
//! \param poll is a pointer to a function which will be called periodically
//! by the SSL module.
//!
//! This function is called by the client application to register a callback
//! which will be called periodically by the SSL layer. The callback period is
//! equivalent to 4x the lwIP slow TCP polling interval, TCP_SLOW_INTERVAL.
//! The default value of TCP_SLOW_INTERVAL is 500mS giving a 2 second SSL poll
//! rate.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_poll(struct ssl_pcb *pcb,
    err_t (* poll)(void *arg, struct ssl_pcb *tpcb))
{
    DEBUG_MSG("ssl_poll 0x%08x\n", (unsigned long)pcb);

    pcb->poll = poll;
}

//*****************************************************************************
//
//! Sets a callback function pointer for use in error conditions.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection for which the callback is being set.
//! \param err is a pointer to a function which will be called in cases where
//! errors are detected.
//!
//! This function is called by the client application to register a callback
//! which can be used to receive error notifications.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_err(struct ssl_pcb *pcb, void (* err)(void *arg, err_t err))
{
    DEBUG_MSG("ssl_err 0x%08x\n", (unsigned long)pcb);

    pcb->errf = err;
}

//*****************************************************************************
//
//! Indicates that the client has read data from the receive buffer.
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection from which data has been read.
//! \param len is the number of bytes of data read from the receive buffer.
//!
//! This function is called by the client application whenever it has removed
//! data from the receive buffer associated with a given SSL PCB. This will
//! typically be in response to a callback made to the function registered
//! via a call to ssl_sent.
//!
//! \return None.
//
//*****************************************************************************
void
ssl_recved(struct ssl_pcb *pcb, u16_t len)
{
    DEBUG_MSG("ssl_recved 0x%08x\n", (unsigned long)pcb);

    //
    // Sanity check - the buffer must have at least len bytes of unread
    // data in it at this point. If not, the client is confused (we certainly
    // are).
    //
    if((pcb->sSslInBuff.end - pcb->sSslInBuff.start) < len)
    {
        DEBUG_MSG("Recved %d bytes but only %d available!\n", len,
                  (pcb->sSslInBuff.end - pcb->sSslInBuff.start));

        //
        // In this case, merely empty the buffer and return.
        //
        pcb->sSslInBuff.start = pcb->sSslInBuff.buf;
        pcb->sSslInBuff.end = pcb->sSslInBuff.buf;
    }
    else
    {
        //
        // We are being told to remove no more data than exists in the buffer.
        // Move the buffer read pointer.
        //
        pcb->sSslInBuff.start += len;

        //
        // If the buffer is now empty, move both pointers back to the
        // beginning.
        //
        if(pcb->sSslInBuff.start == pcb->sSslInBuff.end)
        {
            pcb->sSslInBuff.start = pcb->sSslInBuff.buf;
            pcb->sSslInBuff.end = pcb->sSslInBuff.buf;
        }
    }
}

void
ssl_abort(struct ssl_pcb *pcb)
{
    DEBUG_MSG("ssl_abort 0x%08x\n", (unsigned long)pcb);
    tcp_abort(pcb->tpcb);
}

//*****************************************************************************
//
//! Encode and send data to the remote host
//!
//! \param pcb is the SSL protocol control block identifying the session and
//! connection on which the data is to be sent.
//! \param dataprt is a pointer to the block of data to be sent.
//! \param len is the length of data to be sent.
//!
//! This function accepts a block of clear data and encodes it using the
//! appropriate keys for the SSL session identified by pcb. It then send the
//! data to the remote host.
//!
//! If the caller has registered a sent data callback via ssl_sent, this
//! will be called when the data has been sent and acknowledged by the remote
//! host.
//!
//! \return Returns values as for tcp_write. If no error is detected, ERR_OK
//! is returned. A negative value indicates an error. Valid values can be found
//! in the lwIP header file err.h.
//
//*****************************************************************************
err_t
ssl_write(struct ssl_pcb *pcb, const void *dataptr, u16_t len)
{
    int iRet;
    err_t Error;

    DEBUG_MSG("ssl_write 0x%08x len %d\n", (unsigned long)pcb, len);

    //
    // If there is buffered output data remaining unsent or data in the
    // buffer has yet to be ACKed, we fail the call since we don't support
    // sending additional data until the previous request on this session
    // has been handled. This is sub-optimal but makes the buffer handling
    // a lot easier.
    //
    // Note that, since we are preforming no-copy transmits using lwIP, we
    // cannot move the data in the output buffer until everything in the
    // buffer has been ACKed. If we do, and any retransmission is needed,
    // things break horribly since the data "retransmitted" is not the data
    // that was originally sent.
    //
    if((pcb->ulOutCount != 0) || (pcb->ulBytesPending != 0))
    {
        DEBUG_MSG("Output buffer contains untransmitted data.\n");
        return ERR_BUF;
    }

    //
    // Pack the pending output data (if any) so that start is at zero.
    //
    if (pcb->sSslOutBuff.buf < pcb->sSslOutBuff.start)
    {
        if (pcb->sSslOutBuff.start == pcb->sSslOutBuff.end)
        {
            //
            // The buffer is empty so merely move all the pointers back to
            // the start.
            //
            pcb->sSslOutBuff.start = pcb->sSslOutBuff.buf;
            pcb->sSslOutBuff.end = pcb->sSslOutBuff.buf;
        }
        else
        {
            //
            // The buffer has some remaining data partway through it. Move
            // these back to the start of the buffer.
            //
            memmove(pcb->sSslOutBuff.buf, pcb->sSslOutBuff.start,
                    (pcb->sSslOutBuff.end - pcb->sSslOutBuff.start));
            pcb->sSslOutBuff.end -= (pcb->sSslOutBuff.start -
                                     pcb->sSslOutBuff.buf);
            pcb->sSslOutBuff.start = pcb->sSslOutBuff.buf;
        }
    }

    //
    // Encode the caller's new data into the output buffer.
    //
    iRet = matrixSslEncode(pcb->pSsl, (unsigned char *)dataptr,
                           len, &pcb->sSslOutBuff);
    switch (iRet)
    {
        //
        // Some unspecified error occurred during the encoding process.
        //
        case SSL_ERROR:
            DEBUG_MSG("Error from SSL encode\n");
            return(ERR_BUF);

        //
        // The output buffer is too small to hold the data encoded from the
        // input. Tell the caller that we have a memory problem.
        //
        case SSL_FULL:
            if (pcb->sSslOutBuff.size > SSL_MAX_BUF_SIZE)
            {
                DEBUG_MSG("Out buf size 0x%08x > MAX 0x%08x!\n",
                           pcb->sSslOutBuff.size, SSL_MAX_BUF_SIZE);
            }

            //
            // Tell the caller we can't accomodate this request. Hopefully
            // they will try again with a smaller-sized chunk of data.
            //
            return(ERR_MEM);

        //
        // We will get here in all cases where the encode was processed
        // successfully (positive return codes) or if passed an unexpected
        // error code.
        //
        default:
            if(iRet < 0)
            {
                //
                // The return code indicated an error so respond to the
                // caller.
                //
                DEBUG_MSG("SSL error %d unrecognised!\n", iRet);
                return(ERR_BUF);
            }
            //
            // No error so drop out of the switch to send the data to the
            // remote host.
            //
            break;
    }

    //
    // Send as much of the newly encoded data as we can to the TCP layer.
    //
    Error = send_data_to_tcp(pcb, TRUE);

    //
    // Tell the caller how things went.
    //
    return(Error);
}

void
ssl_setprio(struct ssl_pcb *pcb, u8_t prio)
{
    DEBUG_MSG("ssl_setprio 0x%08x %d\n", (unsigned long)pcb,
              (unsigned long)prio);

    tcp_setprio(pcb->tpcb, prio);
}

err_t
ssl_output(struct ssl_pcb *pcb)
{
    DEBUG_MSG("ssl_output 0x%08x\n", (unsigned long)pcb);
    return(tcp_output(pcb->tpcb));
}

u16_t
ssl_mss(struct ssl_pcb *pcb)
{
    DEBUG_MSG("ssl_mss 0x%08x\n", (unsigned long)pcb);

    return(pcb->tpcb->mss);
}

u16_t
ssl_sndbuf(struct ssl_pcb *pcb)
{
    DEBUG_MSG("ssl_sndbuf 0x%08x\n", (unsigned long)pcb);

    //
    // Return the number of bytes currently free in the output buffer.
    //
    return(pcb->sSslOutBuff.size - (pcb->sSslOutBuff.end -
           pcb->sSslOutBuff.start));
}

