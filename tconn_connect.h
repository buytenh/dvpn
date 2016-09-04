/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015, 2016 Lennert Buytenhek
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
#include "tconn_connect_one.h"

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
	void			*(*new_conn)(void *cookie, void *conn,
					     const uint8_t *id);
	void			(*record_received)(void *cookie,
						   const uint8_t *rec, int len);
	void			(*disconnect)(void *cookie);

	int			state;
	union {
		/* STATE_RESOLVE.  */
		struct {
			struct addrinfo			hints;
			struct iv_getaddrinfo		addrinfo;
			struct iv_timer			resolve_timeout;
		};

		/* STATE_CONNECT.  */
		struct {
			struct tconn_connect_one	tco_connect;
			struct addrinfo			*res;
			struct addrinfo			*rp;
			uint8_t				cnameid[NODE_ID_LEN];
		};

		/* STATE_CONNECTED.  */
		struct {
			struct tconn_connect_one	tco;
			void				*conncookie;
		};

		/* STATE_WAITING_RETRY.  */
		struct {
			struct iv_timer			retry_wait;
		};
	};
};

void tconn_connect_start(struct tconn_connect *tc);
void tconn_connect_destroy(struct tconn_connect *tc);

int tconn_connect_get_rtt(void *conn);
int tconn_connect_get_maxseg(void *conn);
void tconn_connect_record_send(void *conn, const uint8_t *rec, int len);


#endif
