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

#ifndef __PCONN_H
#define __PCONN_H

#include <gnutls/gnutls.h>
#include <iv.h>
#include <stdint.h>

struct pconn {
	int			fd;
	int			role;
	gnutls_x509_privkey_t	key;
	void			*cookie;
	void			(*handshake_done)(void *cookie,
						  const uint8_t *fp, int len);
	void			(*record_received)(void *cookie,
						   const uint8_t *rec, int len);
	void			(*connection_lost)(void *cookie);

	gnutls_certificate_credentials_t cert;
	gnutls_session_t	sess;
	struct iv_fd		ifd;
	int			state;
	struct iv_timer		handshake_timeout;
};

#define PCONN_ROLE_SERVER	0
#define PCONN_ROLE_CLIENT	1

int pconn_start(struct pconn *pc);
int pconn_record_send(struct pconn *pc, const uint8_t *record, int len);
void pconn_destroy(struct pconn *pc);


#endif
