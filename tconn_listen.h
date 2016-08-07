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

struct tconn_listen_socket {
	struct sockaddr_storage		listen_address;
	gnutls_x509_privkey_t		mykey;
	int				numcrts;
	gnutls_x509_crt_t		*mycrts;

	struct iv_fd			listen_fd;
	struct iv_list_head		conn_handshaking;
	struct iv_avl_tree		listen_entries;
};

int tconn_listen_socket_register(struct tconn_listen_socket *tls);
void tconn_listen_socket_unregister(struct tconn_listen_socket *tls);

struct tconn_listen_entry {
	struct tconn_listen_socket	*tls;
	char				*name;
	enum conf_fp_type		fp_type;
	uint8_t				*fingerprint;
	void				*cookie;
	void				*(*new_conn)(void *cookie, void *conn,
						     const uint8_t *id);
	void				(*record_received)(void *cookie,
							   const uint8_t *rec,
							   int len);
	void				(*disconnect)(void *cookie);

	struct iv_avl_node		an;
	struct iv_list_head		connections;
};

int tconn_listen_entry_register(struct tconn_listen_entry *tle);
void tconn_listen_entry_unregister(struct tconn_listen_entry *tle);

int tconn_listen_entry_get_rtt(void *conn);
int tconn_listen_entry_get_maxseg(void *conn);
void tconn_listen_entry_record_send(void *conn, const uint8_t *rec, int len);
void tconn_listen_entry_disconnect(void *conn);


#endif
