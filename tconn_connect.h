/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015 Lennert Buytenhek
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version
 * 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License version 2.1 along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street - Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef __TCONN_CONNECT_H
#define __TCONN_CONNECT_H

#include <gnutls/x509.h>
#include <iv.h>
#include <netdb.h>
#include "conf.h"
#include "iv_getaddrinfo.h"
#include "tconn.h"

struct tconn_connect {
	char			*name;
	char			*hostname;
	char			*port;
	gnutls_x509_privkey_t	mykey;
	int			numcrts;
	gnutls_x509_crt_t	*mycrts;
	enum conf_fp_type	fp_type;
	uint8_t			*fingerprint;
	void			*cookie;
	void			(*set_state)(void *cookie,
					     const uint8_t *id, int up);
	void			(*record_received)(void *cookie,
						   const uint8_t *rec, int len);

	int			state;
	struct iv_timer		rx_timeout;
	union {
		/* STATE_RESOLVE.  */
		struct {
			struct addrinfo		hints;
			struct iv_getaddrinfo	addrinfo;
		};

		/* STATE_CONNECT.  */
		struct {
			struct iv_fd		connectfd;
			struct addrinfo		*res;
			struct addrinfo		*rp;
		};

		/* STATE_{TLS_HANDSHAKE,CONNECTED}.  */
		struct {
			struct iv_fd		tconnfd;
			struct tconn		tconn;
			uint8_t			id[NODE_ID_LEN];
			union {
				/* STATE_TLS_HANDSHAKE.  */
				struct {
					int		have_cnameid;
					uint8_t		cnameid[NODE_ID_LEN];
				};

				/* STATE_CONNECTED.  */
				struct iv_timer		keepalive_timer;
			};
		};
	};
};

void tconn_connect_start(struct tconn_connect *tc);
void tconn_connect_destroy(struct tconn_connect *tc);
int tconn_connect_get_rtt(struct tconn_connect *tc);
int tconn_connect_get_maxseg(struct tconn_connect *tc);
void tconn_connect_record_send(struct tconn_connect *tc,
			       const uint8_t *rec, int len);


#endif
