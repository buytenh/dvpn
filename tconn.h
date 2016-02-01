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

#ifndef __TCONN_H
#define __TCONN_H

#include <gnutls/gnutls.h>
#include <iv.h>
#include <stdint.h>

struct tconn {
	int			fd;
	int			role;
	gnutls_x509_privkey_t	key;
	void			*cookie;
	int			(*verify_key_id)(void *cookie,
						 const uint8_t *id);
	void			(*handshake_done)(void *cookie, char *desc);
	void			(*record_received)(void *cookie,
						   const uint8_t *rec, int len);
	void			(*connection_lost)(void *cookie);

	gnutls_session_t	sess;
	struct iv_fd		ifd;
	gnutls_certificate_credentials_t cert;
	int			state;

	int			io_error;
	struct iv_task		rx_task;
	uint8_t			rx_buf[32768];
	int			rx_start;
	int			rx_end;
	int			rx_eof;
	struct iv_task		tx_task;
	uint8_t			tx_buf[32768];
	int			tx_bytes;
};

#define TCONN_ROLE_SERVER	0
#define TCONN_ROLE_CLIENT	1

int tconn_start(struct tconn *pc);
int tconn_record_send(struct tconn *pc, const uint8_t *record, int len);
void tconn_destroy(struct tconn *pc);


#endif
