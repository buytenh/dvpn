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

#ifndef __TCONN_CONNECT_ONE_H
#define __TCONN_CONNECT_ONE_H

#include <gnutls/x509.h>
#include <iv.h>
#include "conf.h"
#include "tconn.h"

struct tconn_connect_one {
	char			*name;
	struct sockaddr		*addr;
	socklen_t		addrlen;
	gnutls_x509_privkey_t	mykey;
	int			numcrts;
	gnutls_x509_crt_t	*mycrts;
	enum conf_fp_type	fp_type;
	uint8_t			*fingerprint;
	uint8_t			*cnameid;
	void			*cookie;
	void			(*connected)(void *cookie, const uint8_t *id);
	void			(*record_received)(void *cookie,
						   const uint8_t *rec, int len);
	void			(*connection_failed)(void *cookie);

	int			state;

	/* STATE_{CONNECT,TLS_HANDSHAKE,CONNECTED}.  */
	struct iv_timer		rx_timeout;
	struct iv_fd		fd;

	/* STATE_{TLS_HANDSHAKE,CONNECTED}.  */
	struct tconn		tconn;
	uint8_t			id[NODE_ID_LEN];

	/* STATE_CONNECTED.  */
	struct iv_timer		keepalive_timer;
};

int tconn_connect_one_connect(struct tconn_connect_one *tco);
void tconn_connect_one_disconnect(struct tconn_connect_one *tco);
int tconn_connect_one_get_rtt(struct tconn_connect_one *tco);
int tconn_connect_one_get_maxseg(struct tconn_connect_one *tco);
int tconn_connect_one_record_send(struct tconn_connect_one *tco,
				  const uint8_t *rec, int len);


#endif
