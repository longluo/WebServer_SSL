/*
 *	matrixConfig.h
 *	Release $Name: MATRIXSSL_1_8_6_OPEN $
 *
 *	Configuration settings for building the MatrixSSL library.
 *	These options affect the size and algorithms present in the library.
 */
/*
 *	Copyright (c) PeerSec Networks, 2002-2008. All Rights Reserved.
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from PeerSec Networks
 *	at http://www.peersec.com
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

/******************************************************************************/
/*
 * Luminary Micro Notes:
 * ---------------------
 *
 * 1. The contents of this header have been modified for use in a single-
 *    threaded environment with no available file system.
 * 2. Added reference to the Luminary function header uartstdio.h
 * 3. Added label MAX_SSL_HEAP_SIZE to define the amount of RAM that will
 *    be set aside for SSL use (via psMalloc/psFree APIs). There is already a
 *    definition MAX_MEMORY_USAGE in psMalloc.h but it defaults to 0 which
 *    doesn't help us a lot.
 */
/******************************************************************************/

#ifndef _h_MATRIXCONFIG
#define _h_MATRIXCONFIG

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/*
    Pull in Luminary Micro debug function headers.
*/
#include "uartstdio.h"

/******************************************************************************/
/*
    Define the maximum size of the heap set aside for MatrixSSL use.

    TODO: Refine this value to suit your application needs.
*/
#define MAX_SSL_HEAP_SIZE (22 * 1024)

/******************************************************************************/
/*
	Define the number of sessions to cache here.
	Minimum value is 1
	Session caching provides such an increase in performance that it isn't
	an option to disable.
*/
#ifdef WIN32
#define SSL_SESSION_TABLE_SIZE	32
#else
#define SSL_SESSION_TABLE_SIZE  8
#endif

/******************************************************************************/
/*
	Define the following to enable various cipher suites
	At least one of these must be defined.  If multiple are defined,
	the handshake will determine which is best for the connection.
*/
#define USE_SSL_RSA_WITH_RC4_128_MD5
#define USE_SSL_RSA_WITH_RC4_128_SHA
#ifdef WIN32
#define USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
#endif

/******************************************************************************/
/*
	Support for encrypted private key files, using 3DES
*/
#define USE_ENCRYPTED_PRIVATE_KEYS

/******************************************************************************/
/*
	Support for client side SSL
*/
#define USE_CLIENT_SIDE_SSL
#define USE_SERVER_SIDE_SSL


/******************************************************************************/
/*
	Use native 64 bit integers (long longs)
*/
#undef USE_INT64

/******************************************************************************/
/*
	Hi-res POSIX timer.  Use rdtscll() for timing routines in linux.c
*/
/* #define USE_RDTSCLL_TIME */

/******************************************************************************/
/*
	Support for multithreading environment.  This should be enabled
	if multiple SSL sessions will be active at the same time in 
	different threads.  The library will still be single threaded,
	but will serialize access to the session cache with a mutex.
*/
#ifdef WIN32
#define USE_MULTITHREADING
#else
#undef USE_MULTITHREADING
#endif

/******************************************************************************/
/*
	Support for file system.
*/
#ifdef WIN32
#define USE_FILE_SYSTEM
#else
#undef USE_FILE_SYSTEM
#endif

#ifdef __cplusplus
}
#endif

#endif /* _h_MATRIXCONFIG */

/******************************************************************************/

