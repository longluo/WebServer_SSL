/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwiplib.h"
#include "httpsd.h"
#include "fs.h"
#include "ssl.h"
#include <string.h>

struct https_state {
  struct fs_file *handle;
  char *file;
  u32_t left;
  u8_t retries;
};

#define HTTPS_PORT 443

/*-----------------------------------------------------------------------------------*/
static void
conn_err(void *arg, err_t err)
{
  struct https_state *hs;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https conn_err %"X32_F"\n", arg));
  
  hs = arg;
  if(hs->handle) {
    fs_close(hs->handle);
    hs->handle = NULL;
  }
  mem_free(hs);
}
/*-----------------------------------------------------------------------------------*/
static void
close_conn(struct ssl_pcb *pcb, struct https_state *hs)
{
  LWIP_DEBUGF(HTTPSD_DEBUG, ("https close_conn %"X32_F"\n", pcb));
      
  ssl_arg(pcb, NULL);
  ssl_sent(pcb, NULL);
  ssl_recv(pcb, NULL);
  if(hs->handle) {
    fs_close(hs->handle);
    hs->handle = NULL;
  }
  mem_free(hs);
  ssl_close(pcb);
}
/*-----------------------------------------------------------------------------------*/
static void
send_data(struct ssl_pcb *pcb, struct https_state *hs)
{
  err_t err;
  u16_t len;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https send_data %"X32_F"\n", pcb));
  
  if(hs->left == 0)
  {
    int count;
    static char buf[3][2*TCP_MSS];
    static int index = 0;

    count = 2*TCP_MSS;
    hs->file = buf[index];
    index++;
    if(index > 2) {
      index = 0;
    }
    if(count > (2 * ssl_mss(pcb))) {
      count = 2 * ssl_mss(pcb);
    }
    count = fs_read(hs->handle, hs->file, count);
    if(count < 0)
    {
      fs_close(hs->handle);
      hs->handle = NULL;
      close_conn(pcb, hs);
      return;
    }
    hs->left = count;
  }

  /* We cannot send more data than space available in the send
     buffer. */     
  if (ssl_sndbuf(pcb) < hs->left) {
    len = ssl_sndbuf(pcb);
  } else {
    len = hs->left;
  }
  if(len > (2 * ssl_mss(pcb)))
  {
    len = 2 * ssl_mss(pcb);
  }

  do {
    err = ssl_write(pcb, hs->file, len);
    if (err == ERR_MEM) {
      len /= 2;
    }
  } while (err == ERR_MEM && len > 1);  

  if (err == ERR_OK) {
    ssl_output(pcb);
    hs->file += len;
    hs->left -= len;
  /*  } else {
    printf("send_data: error %s len %d %d\n", lwip_strerr(err), len, ssl_sndbuf(pcb));*/
  }
}
/*-----------------------------------------------------------------------------------*/
static err_t
https_poll(void *arg, struct ssl_pcb *pcb)
{
  struct https_state *hs;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https_poll %"X32_F"\n", pcb));
  
  hs = arg;
  
  /*  printf("Poll\n");*/
  if (hs == NULL) {
    /*    printf("Null, close\n");*/
    ssl_abort(pcb);
    return ERR_ABRT;
  } else {
    ++hs->retries;
    if (hs->retries == 4) {
      ssl_abort(pcb);
      return ERR_ABRT;
    }
    send_data(pcb, hs);
  }

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
https_sent(void *arg, struct ssl_pcb *pcb, u16_t len)
{
  struct https_state *hs;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https_send %"X32_F" len %"U16_F"\n", pcb, len));
  
  hs = arg;

  hs->retries = 0;
  
  send_data(pcb, hs);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
https_recv(void *arg, struct ssl_pcb *pcb, unsigned char *p, int len)
{
  int i;
  struct fs_file *file;
  struct https_state *hs;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https_recv %"X32_F"\n", pcb));
  
  hs = arg;

  if (p != NULL)
  {
    /* Inform TCP that we have taken the data. */
    ssl_recved(pcb, len);
    
    if (hs->handle == NULL)
    {    
        if (strncmp((char *)p, "GET ", 4) == 0)
        {
	        for(i = 0; i < 40; i++)
            {
	           if (((char *)p + 4)[i] == ' ' ||
	               ((char *)p + 4)[i] == '\r' ||
	               ((char *)p + 4)[i] == '\n')
               {
	               ((char *)p + 4)[i] = 0;
	           }
	        }

            if (*(char *)(p + 4) == '/' &&
                *(char *)(p + 5) == 0)
            {
                LWIP_DEBUGF(HTTPSD_DEBUG, ("GET /index.html\n"));        
                file = fs_open("/index.html");
            }
            else
            {
                LWIP_DEBUGF(HTTPSD_DEBUG, ("GET %s\n", (char *)p + 4));
                file = fs_open((char *)p + 4);
                if(file == NULL)
                {
                    LWIP_DEBUGF(HTTPSD_DEBUG, ("File not found - "
                                               "using /404.html\n"));
                    file = fs_open("/404.html");
                }
            }
    
            hs->handle = file;
            hs->file = file->data;
            hs->left = file->len;
            hs->retries = 0;
	        /*	printf("data %p len %ld\n", hs->file, hs->left);*/

	        send_data(pcb, hs);

	        /* Tell SSL that we wish be to informed of data that has been
	           successfully sent by a call to the https_sent() function. */
	        ssl_sent(pcb, https_sent);
        }
        else
        {
	       close_conn(pcb, hs);
        }
    }
  }
  else
  {
    //
    // The SSL layer told us that the TCP connection was closed by the remote
    // host so tidy up.
    //
    close_conn(pcb, hs);
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
https_accept(void *arg, struct ssl_pcb *pcb, err_t err)
{
  struct https_state *hs;

  LWIP_DEBUGF(HTTPSD_DEBUG, ("https_accept %"X32_F"\n", pcb));

  ssl_setprio(pcb, TCP_PRIO_MIN);
  
  /* Allocate memory for the structure that holds the state of the
     connection. */
  hs = mem_malloc(sizeof(struct https_state));

  if (hs == NULL) {
    //printf("https_accept: Out of memory\n");
    return ERR_MEM;
  }
  
  /* Initialize the structure. */
  hs->handle = NULL;
  hs->file = NULL;
  hs->left = 0;
  hs->retries = 0;
  
  /* Tell TCP that this is the structure we wish to be passed for our
     callbacks. */
  ssl_arg(pcb, hs);

  /* Tell TCP that we wish to be informed of incoming data by a call
     to the https_recv() function. */
  ssl_recv(pcb, https_recv);

  ssl_err(pcb, conn_err);
  
  ssl_poll(pcb, https_poll);
  
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------
 * 
 * Initialize the HTTPS server - Initialize the SSL library initialised, read
 * appropriate server keys, create a socket and wait for incoming connections.
 * 
 * Returns: 0 on success, -1 on error
 * 
 *-----------------------------------------------------------------------------------*/
int httpsd_init(void)
{
    struct ssl_pcb *pcb;

    LWIP_DEBUGF(HTTPSD_DEBUG, ("httpsd_init"));
    
    //
    // Create a new socket and listen for incoming connections on port 443
    // (the standard port used for HTTPS communication).
    //
    pcb = ssl_new();
    ssl_bind(pcb, IP_ADDR_ANY, HTTPS_PORT);
    ssl_listen(pcb);
    ssl_accept(pcb, https_accept);
    
    return(0);
}

/*-----------------------------------------------------------------------------------*/

