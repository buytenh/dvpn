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

#ifndef __LISTEN_H
#define __LISTEN_H

#include <gnutls/x509.h>
#include "conf.h"

struct listening_socket
{
	struct sockaddr_storage	listen_address;
	gnutls_x509_privkey_t	key;

	struct iv_fd		listen_fd;
	struct iv_list_head	listen_entries;
};

int listening_socket_register(struct listening_socket *ls);
void listening_socket_unregister(struct listening_socket *ls);

struct listen_entry
{
	struct listening_socket	*ls;
	char			*tunitf;
	char			*name;
	uint8_t			fingerprint[20];
	int			is_peer;
	void			*cookie;
	void			(*set_state)(void *cookie, int up);

	struct iv_list_head	list;
	struct tun_interface	tun;
	struct client_conn	*current;
};

int listen_entry_register(struct listen_entry *le);
void listen_entry_unregister(struct listen_entry *le);


#endif
