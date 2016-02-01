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

#ifndef __TCONN_LISTEN_H
#define __TCONN_LISTEN_H

#include <gnutls/x509.h>
#include "conf.h"
#include "tun.h"

struct tconn_listen_socket
{
	struct sockaddr_storage	listen_address;
	gnutls_x509_privkey_t	key;

	struct iv_fd		listen_fd;
	struct iv_list_head	listen_entries;
};

int tconn_listen_socket_register(struct tconn_listen_socket *tls);
void tconn_listen_socket_unregister(struct tconn_listen_socket *tls);

struct tconn_listen_entry
{
	struct tconn_listen_socket	*tls;
	char				*tunitf;
	char				*name;
	uint8_t				*fingerprint;
	void				*cookie;
	void				(*set_state)(void *cookie, int up);

	struct iv_list_head		list;
	struct tun_interface		tun;
	struct client_conn		*current;
};

int tconn_listen_entry_register(struct tconn_listen_entry *tle);
void tconn_listen_entry_unregister(struct tconn_listen_entry *tle);


#endif
