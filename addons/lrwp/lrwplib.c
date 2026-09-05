/************************************************************************
               Copyright (c) 1997 by Total Control Software
                         All Rights Reserved
------------------------------------------------------------------------

Module Name:    lrwplib.c

Description:    Small library of routines to assist with the creation
                of LRWP Peer applications.

Creation Date:  1/5/98 9:47:27PM
Updated:        1999/08/18, by Xitami Team <xitami@imatix.com> for LRWP 2.0
Updated:        1999/11/05, by Pascal Antonnaux <pascal@imatix.com>
                            for posted size in context 

# License:      This is free software.  You may use this software for any
#               purpose including modification/redistribution, so long as
#               this header remains intact and that you do not claim any
#               rights of ownership or authorship of this software.  This
#               software has been tested, but no warranty is expressed or
#               implied.

************************************************************************/

#include "lrwplib.h"

#define LENGTH_LEN          9           /* Digits in length val to/from peer */
#define LENGTH_FORMAT_ULONG "%09uld"    /* above for int; this for ulong     */

#define LRWP_STRING_DELIM      "\xFF"   /* Delimiter as string; to send      */
#define LRWP_STRING_DELIM_CHAR '\xFF'   /* Delimiter as char; to search for  */

#define ALLOC_INCR  1024

static int
read_full_TCP(
    sock_t handle,                      /*  Socket handle                    */
    void *buffer,                       /*  Buffer to receive data           */
    size_t length                       /*  Full amount of data to read      */
    );

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_connect

    Connects to the LRWP agent running in Xitami on host and port.  Sends
    the given appname to use as the URI alias that will trigger requests to
    be sent to this peer.  If vhost is given, this peer will only be sent
    requests origininating from that virtual host.  This function assumes
    that the LRWP structure is uninitialized and clears it before use.

    Returns NULL on success and a pointer to an error message otherwise.
    ---------------------------------------------------------------------[>]-*/

char* lrwp_connect(LRWP* lrwp,          /* pointer to UNCONNECTED LRWP object*/
                   char* appname,       /* Name or alias of Peer app         */
                   char* host,          /* hostname/IP address to connect to */
                   char* port,          /* string containing port number     */
                   char* vhost)         /* optional virtual hostname         */
{
    return lrwp2_connect(lrwp, appname, host, port, vhost, NULL);
}


/*  ---------------------------------------------------------------------[<]-
    Function: lrwp2_connect

    Connects to the LRWP 2.0 agent running in Xitami on host and port.  Sends
    the given appname to use as the URI alias that will trigger requests to
    be sent to this peer.  If vhost is given, this peer will only be sent
    requests origininating from that virtual host.  If the passphrase is
    supplied a LRWP 2.0 connection will be attempted using that passphrase
    to do the authentication, otherwise a LRWP 1.0 connection will be used. 
    This function assumes that the LRWP structure is uninitialized and 
    clears it before use.

    Returns NULL on success and a pointer to an error message otherwise.
    ---------------------------------------------------------------------[>]-*/

char* lrwp2_connect(LRWP* lrwp,         /* pointer to UNCONNECTED LRWP object*/
                    char* appname,      /* Name or alias of Peer app         */
                    char* host,         /* hostname/IP address to connect to */
                    char* port,         /* string containing port number     */
                    char* vhost,        /* optional virtual hostname         */
		    char* passphrase)   /* optional authentication passphrase*/
{
    static char buf[1024];
    char        sizebuf[LENGTH_LEN+1];
    int         len;

    /* Initialize LRWP structure.  Assumes this is first use. */
    lrwp->sock      = 0;
    lrwp->cgi       = NULL;
    lrwp->post_data = NULL;
    lrwp->outbuf    = NULL;
    lrwp->size      = 0;
    lrwp->allocated = 0;
    lrwp->post_size = 0;

    /* Attempt the connection */
    ip_nonblock = FALSE;                /*  Use blocking socket i/o          */
    lrwp->sock = connect_TCP(host, port);
    if (lrwp->sock == INVALID_SOCKET) {
        sprintf(buf, "ERROR: Unable to connect (%s)", sockmsg());
        return buf;
    }

    /* send the startup string.  We use a LRWP 2.0 startup string if we 
     * have a passphrase, and thus expect to need to do authentication
     *
     * LRWP connection request contains:
     *   LRWP 1.0: applicationname 0xFF virtualhostname 0xFF filterext [0xFF]
     *   LRWP 2.0: 0xFF proto_major "." proto_minor 0xFF applicationname
     *             0xFF virtualhostname 0xFF
     */
    if (passphrase)
	sprintf(buf, LRWP_STRING_DELIM "2.0" LRWP_STRING_DELIM "%s"   /*LRWP2*/
		     LRWP_STRING_DELIM "%s"  LRWP_STRING_DELIM,
		     appname, vhost ? vhost : "");
    else
        sprintf(buf, "%s" LRWP_STRING_DELIM "%s" LRWP_STRING_DELIM "%s",  /*1*/
		     appname, vhost?vhost:"", "");

    if (write_TCP(lrwp->sock, buf, strlen(buf)) == SOCKET_ERROR) {
        sprintf(buf, "ERROR: Unable to send startup string (%s)", sockmsg());
	lrwp_close(lrwp);
        return buf;
    }

    /* wait for an acknowledgement... */
    len = read_TCP(lrwp->sock, buf, sizeof(buf)-1);
    if (len == SOCKET_ERROR) {
        sprintf(buf, "ERROR: Unable to receive acknowledgement string (%s)", 
		     sockmsg());
	lrwp_close(lrwp);
        return buf;
    }
    buf[len] = '\0';

    /* At this point we will either be acknowledged, or we will be
     * challenged.  If we are challenged, we respond using our
     * passphrase.
     */
#define CHALLENGE_IND ("CHALLENGE" LRWP_STRING_DELIM)
#define CHALLENGE_LEN 10
#define REJECTED_IND  ("REJECTED"  LRWP_STRING_DELIM)
#define REJECTED_LEN  9

    if (streq(buf, "OK") || streq(buf, "OK" LRWP_STRING_DELIM))
        return NULL;                         /* Connected, no problems */
    else if (strncmp(buf, CHALLENGE_IND, CHALLENGE_LEN) == 0) {
	/* We've been challenged -- either the buffer, or our input
	 * should contain the challenge length and string.
	 */
	int i, size, passphraselen;
	byte *challengeResponse = NULL;

        if (len < CHALLENGE_LEN + LENGTH_LEN) {
	    /* Don't have (all of) the length of the challenge string */
            int got = read_full_TCP(lrwp->sock, (buf + len), 
		                    (CHALLENGE_LEN + LENGTH_LEN - len));
	    if (got == SOCKET_ERROR) {
		sprintf(buf, "ERROR: Unable to receive LRWP challenge len (%s)",
			     sockmsg());
	        lrwp_close(lrwp);
                return buf;
	    }
	    else
		len += got;
	}

	ASSERT(len >= CHALLENGE_LEN + LENGTH_LEN);
	memcpy(sizebuf, (buf + CHALLENGE_LEN), LENGTH_LEN);
	sizebuf[CHALLENGE_LEN] = '\0';
        size = atoi(sizebuf);

	/* Ensure we'll have room to receive the challenge.  The current
	 * LRWP spec means we should easily be able to fit it in our
	 * buffer.
	 */
        if (size < 0 || CHALLENGE_LEN + LENGTH_LEN + size > sizeof(buf)) {
	    sprintf(buf, "ERROR: Cannot process challenge (len: %s)",
		          sizebuf);
	    lrwp_close(lrwp);
            return buf;
	}

	/* Make sure we've got the LRWP challenge itself. */
	if (len < CHALLENGE_LEN + LENGTH_LEN + size) {
            int got = read_full_TCP(lrwp->sock, (buf + len), 
		                    (CHALLENGE_LEN + LENGTH_LEN + size - len));
	    if (got == SOCKET_ERROR) {
		sprintf(buf, "ERROR: Unable to receive LRWP challenge len (%s)",
			     sockmsg());
	        lrwp_close(lrwp);
                return buf;
	    }
	    else
		len += got;
	}

        ASSERT(len == CHALLENGE_LEN + LENGTH_LEN + size);
	buf[len] = '\0';

	/* Process response, in place */
        passphraselen = strlen(passphrase);

        for (i = 0, challengeResponse=(byte *)(buf+CHALLENGE_LEN+LENGTH_LEN);
             i < size;
	     ++i, ++challengeResponse)

             *challengeResponse ^= (passphrase[i % passphraselen]);

        /* Now send back the LRWP challenge response, length and data */
        if (write_TCP(lrwp->sock, (buf + CHALLENGE_LEN), (LENGTH_LEN + size)) 
            == SOCKET_ERROR) {

            sprintf(buf, "ERROR: Unable to send LRWP challenge response (%s)", 
		         sockmsg());
	    lrwp_close(lrwp);
            return buf;
        } 

	/* Finally, check to see if we're accepted now */
        len = read_TCP(lrwp->sock, buf, sizeof(buf)-1);
        if (len == SOCKET_ERROR) {
            sprintf(buf, "ERROR: Unable to receive LRWP challenge ack (%s)", 
		         sockmsg());
	    lrwp_close(lrwp);
            return buf;
        }
	buf[len] = '\0';
        if (streq(buf, "OK") || streq(buf, "OK" LRWP_STRING_DELIM)) {
	    return NULL;                   /* We're accepted, no trouble */
        } else if (strncmp(buf, REJECTED_IND, REJECTED_LEN) == 0) {
	    /* XXX: Assume we got the whole rejection message in one read */

	    /* Tidy up the reject message for the viewer */
	    buf[len-1] = '\0';
	    ASSERT(REJECTED_LEN >= 7);
	    memcpy(buf + (REJECTED_LEN - 7), "ERROR: ", 7);

	    lrwp_close(lrwp);
	    return (buf + REJECTED_LEN - 7);
	} else {
	    lrwp_close(lrwp);
            return buf;                    /* Rejection message */
	}
    } else if (strncmp(buf, REJECTED_IND, REJECTED_LEN) == 0) {
	/* XXX: Assume we got the whole rejection message in one read */

	/* Tidy up the reject message for the viewer */
	buf[len-1] = '\0';
	ASSERT(REJECTED_LEN >= 7);
	memcpy(buf + (REJECTED_LEN - 7), "ERROR: ", 7);

	lrwp_close(lrwp);
	return (buf + REJECTED_LEN - 7);
    } else {
	/* Something else -- treat it like an error. */
	lrwp_close(lrwp);
        return buf;
    }
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_accept_request

    This funation waits for and recieves a request from the LRWP agent, and
    populates the LRWP structure with the request data.

    Returns 0 on success and -1 otherwise.
    ---------------------------------------------------------------------[>]-*/

int  lrwp_accept_request(LRWP* lrwp)    /* pointer to CONNECTED LRWP object  */
{
    char
        sizebuf [LENGTH_LEN + 1];
    int
        len,
        size;
    DESCR
        descr;
    char
        *temp;

    /* read the size of the CGI environment                                  */
    len = read_full_TCP(lrwp->sock, sizebuf, LENGTH_LEN);
    if (len == SOCKET_ERROR 
    || len != LENGTH_LEN)
        return (-1);

    sizebuf [len] = 0;
    size          = atoi (sizebuf);

    /*  read the CGI environment data                                        */
    temp = mem_alloc (size + 1);
    if (temp == NULL)
        return (-1);

    len = read_full_TCP (lrwp->sock, temp, size);
    if (len == SOCKET_ERROR 
    ||  len != size)
      {
        mem_free (temp);
        return (-1);
      }

    /*  and convert it to a Symbol Table                                     */
    descr.size = size;
    descr.data = temp;
    lrwp-> cgi = descr2symb (&descr);
    mem_free (temp);

    /*  now read the size of the post data                                   */
    len = read_full_TCP (lrwp-> sock, sizebuf, LENGTH_LEN);
    if (len == SOCKET_ERROR 
    ||  len != LENGTH_LEN)
      {
        sym_delete_table (lrwp->cgi);
        lrwp->cgi = NULL;
        return (-1);
      }
    sizebuf [len] = 0;
    size = atoi (sizebuf);

    /*  and finally, read the post data, if any                              */
    if (size) 
      {
        lrwp-> post_data = mem_alloc (size + 1);
        if (lrwp-> post_data)
          {
            len = read_full_TCP (lrwp->sock, lrwp-> post_data, size);
            if (len == SOCKET_ERROR
            ||  len != size)
              {
                sym_delete_table (lrwp->cgi);
                mem_free (lrwp->post_data);
                lrwp-> cgi       = NULL; 
                lrwp-> post_data = NULL;
                return (-1);
              }
            else
              {
                lrwp-> post_data [size] = '\0';
                lrwp-> post_size        = size;
              }
          }
        else
            lrwp-> post_data = mem_strdup ("");
    }
    else
        lrwp-> post_data = mem_strdup ("");

    return 0;
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_send_string

    This function appends a string to the response buffer.
    lrwp_finish_request() must be called to send the response back to Xitami.

    Returns 0 on success and -1 otherwise.
    ---------------------------------------------------------------------[>]-*/

int  lrwp_send_string(LRWP* lrwp,       /* pointer to CONNECTED LRWP object  */
                      char* st)         /* an ouput string                   */
{
    return lrwp_send_data(lrwp, st, strlen(st));
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_send_data

    Appends a buffer of (possibly binary) data of the specified size to
    the response buffer.  lrwp_finish_request() must be called to send the
    response back to Xitami.

    Returns 0 on success and -1 otherwise.
    ---------------------------------------------------------------------[>]-*/

int  lrwp_send_data(LRWP* lrwp,         /* pointer to CONNECTED LRWP object  */
                    void* data,         /* pointer to a data buffer          */
                    size_t len)         /* size of the data buffer           */
{
    char*   newPtr;
    size_t  newAlloc;

    /* reallocate if necessary */
    if ((lrwp->size + len) > lrwp->allocated) {
        newAlloc = max(lrwp->allocated + len, lrwp->allocated + ALLOC_INCR);
        if (! lrwp->outbuf)
            newPtr = mem_alloc(newAlloc);
        else
            newPtr = mem_realloc(lrwp->outbuf, newAlloc);
        if (!newPtr)
            return -1;
        lrwp->outbuf = newPtr;
        lrwp->allocated = newAlloc;
    }
    memcpy(lrwp->outbuf + lrwp->size, data, len);
    lrwp->size += len;
    return 0;
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_finish_request

    Completes the request by sending the response buffer back to Xitami
    and prepares the lwrp structure to receive another request.

    Returns 0 on success and -1 otherwise.
    ---------------------------------------------------------------------[>]-*/

int  lrwp_finish_request(LRWP* lrwp)    /* pointer to CONNECTED LRWP object  */
{
    char    sizebuf[LENGTH_LEN+1];

    sprintf(sizebuf, LENGTH_FORMAT_ULONG, lrwp->size);
    if (write_TCP(lrwp->sock, sizebuf, LENGTH_LEN) == SOCKET_ERROR) {
        lrwp_cleanup(lrwp);
        return -1;
    }

    if (write_TCP(lrwp->sock, lrwp->outbuf, lrwp->size) == SOCKET_ERROR) {
        lrwp_cleanup(lrwp);
        return -1;
    }
    lrwp_cleanup(lrwp);
    return 0;
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_close

    Closes the connection to Xitami.

    Returns 0 on success and -1 otherwise.
    ---------------------------------------------------------------------[>]-*/

int  lrwp_close(LRWP* lrwp)             /* pointer to CONNECTED LRWP object  */
{
    close_socket(lrwp->sock);
    lrwp->sock = INVALID_SOCKET;
    lrwp_cleanup(lrwp);
    return 0;
}

/*  ---------------------------------------------------------------------[<]-
    Function: lrwp_cleanup

    Cleans up the LRWP structure.

    ---------------------------------------------------------------------[>]-*/

void lrwp_cleanup(LRWP* lrwp)
{
    if (lrwp->cgi)
        sym_delete_table(lrwp->cgi);

    if (lrwp->post_data)
        mem_free(lrwp->post_data);

    if (lrwp->outbuf)
        mem_free(lrwp->outbuf);

    lrwp->cgi        = NULL;
    lrwp->post_data  = NULL;
    lrwp->outbuf     = NULL;
    lrwp->size       = 0;
    lrwp->allocated  = 0;
    lrwp-> post_size = 0;

}


/*  -------------------------------------------------------------------------
    Function: read_full_TCP

    Helper function to read the full number of bytes specified from the socket.

    -------------------------------------------------------------------------*/
static int
read_full_TCP(
    sock_t handle,                      /*  Socket handle                    */
    void *buffer,                       /*  Buffer to receive data           */
    size_t length                       /*  Full amount of data to read      */
    )
{
    size_t  numRead = 0;
    int     chunkLen;

    while (numRead < length) {
        chunkLen = read_TCP(handle, ((char*)buffer)+numRead, length-numRead);
        if (chunkLen == SOCKET_ERROR)
            return SOCKET_ERROR;
        numRead += chunkLen;
    }
    return numRead;
}


