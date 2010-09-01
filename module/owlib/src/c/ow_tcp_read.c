/*
$Id$
    OWFS -- One-Wire filesystem
    OWHTTPD -- One-Wire Web Server
    Written 2003 Paul H Alfille
    email: palfille@earthlink.net
    Released under the GPL
    See the header file: ow.h for full attribution
    1wire/iButton system from Dallas Semiconductor
*/

/* ow_net holds the network utility routines. Many stolen unashamedly from Steven's Book */
/* Much modification by Christian Magnusson especially for Valgrind and embedded */
/* non-threaded fixes by Jerry Scharf */

#include <config.h>
#include "owfs_config.h"
#include "ow.h"
#include "ow_counters.h"

/* Wait for something to be readable or timeout */
GOOD_OR_BAD tcp_wait(FILE_DESCRIPTOR_OR_ERROR file_descriptor, const struct timeval *ptv)
{
	int select_result;
	fd_set readset;
	struct timeval tv = { ptv->tv_sec, ptv->tv_usec, };

	/* Initialize readset */
	FD_ZERO(&readset);
	FD_SET(file_descriptor, &readset);

	while (1) {
		// Read if it doesn't timeout first
		select_result = select(file_descriptor + 1, &readset, NULL, NULL, &tv);
		if (select_result < 0) {
			if (errno == EINTR) {
				continue;		/* interrupted */
			}
			return gbBAD;		/* error */
		} else if (select_result == 0) {
			return gbBAD;		/* timeout */
		} else {
			// Is there something to read?
			if (FD_ISSET(file_descriptor, &readset)) {
				break;
			}
		}
	}
	return gbGOOD;
}

/* Read "n" bytes from a descriptor. */
/* Stolen from Unix Network Programming by Stevens, Fenner, Rudoff p89 */
/* return < 0 if failure */
ZERO_OR_ERROR tcp_read(FILE_DESCRIPTOR_OR_ERROR file_descriptor, BYTE * buffer, size_t requested_size, const struct timeval * ptv, size_t * chars_in)
{
	size_t nleft_to_read = requested_size ;

	LEVEL_DEBUG("attempt %d bytes Time:(%ld,%ld)",(int)requested_size,ptv->tv_sec,ptv->tv_usec ) ;
	*chars_in = 0 ;
	while (nleft_to_read > 0) {
		int select_result;
		ssize_t nread;
		fd_set readset;
		struct timeval tv = { ptv->tv_sec, ptv->tv_usec, };

		/* Initialize readset */
		FD_ZERO(&readset);
		FD_SET(file_descriptor, &readset);

		/* Read if it doesn't timeout first */
		select_result = select(file_descriptor + 1, &readset, NULL, NULL, &tv);
		if (select_result > 0) {
			/* Is there something to read? */
			if (FD_ISSET(file_descriptor, &readset) == 0) {
				LEVEL_DEBUG("tcp_error -- nothing avialable to read");
				return -EIO;	/* error */
			}
			//update_max_delay(pn);
			errno = 0 ;
			nread = read(file_descriptor, &buffer[*chars_in], nleft_to_read) ;
			if ( nread < 0 ) {
				if (errno == EINTR) {
					nread = 0;	/* and call read() again */
				} else {
					LEVEL_DATA("Network data read error errno=%d %s", errno, strerror(errno));
					STAT_ADD1(NET_read_errors);
					return -EIO;
				}
			} else if (nread == 0) {
				break;			/* EOF */
			}
			TrafficInFD("NETREAD", &buffer[*chars_in], nread, file_descriptor ) ;
			nleft_to_read -= nread;
			*chars_in += nread ;
		} else if (select_result < 0) {	/* select error */
			if (errno == EINTR) {
				/* select() was interrupted, try again */
				continue;
			}
			ERROR_DATA("Selection error (network)");
			return -EINTR;
		} else {				/* timed out */
			LEVEL_CONNECT("TIMEOUT after %d bytes", requested_size - nleft_to_read);
			return -EAGAIN;
		}
	}
	LEVEL_DEBUG("requested=%d not_found=%d",(int)requested_size, (int) nleft_to_read ) ;
	return 0;
}

void tcp_read_flush( FILE_DESCRIPTOR_OR_ERROR file_descriptor)
{
	ASCII buffer[16];
	ssize_t nread;
	int flags = fcntl(file_descriptor, F_GETFL, 0);

	// Apparently you can test for GET_FL success like this
	// see http://www.informit.com/articles/article.asp?p=99706&seqNum=13&rl=1
	if (flags < 0) {
		return;
	}

	if (fcntl(file_descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
 		return;
	}
	while ((nread = read(file_descriptor, (BYTE *) buffer, 16)) > 0) {
		Debug_Bytes("tcp_read_flush", (BYTE *) buffer, nread);
		continue;
	}

	fcntl(file_descriptor, F_SETFL, flags);
}
