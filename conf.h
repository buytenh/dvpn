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

#ifndef __CONF_H
#define __CONF_H

#include <iv_avl.h>
#include <stdint.h>
#include <sys/socket.h>

enum conf_fp_type {
	CONF_FP_TYPE_ANY,
	CONF_FP_TYPE_CNAME,
	CONF_FP_TYPE_MATCH,
};

#include "dgp_connect.h"
#include "dgp_listen.h"
#include "tconn_connect.h"
#include "tconn_listen.h"
#include "tun.h"

struct conf {
	char			*node_name;
	char			*private_key;
	char			*role_key;
	struct iv_avl_tree	connect_entries;
	struct iv_avl_tree	listening_sockets;
};

enum conf_peer_type {
	CONF_PEER_TYPE_INVALID,
	CONF_PEER_TYPE_DBONLY,
	CONF_PEER_TYPE_EPEER,
	CONF_PEER_TYPE_CUSTOMER,
	CONF_PEER_TYPE_TRANSIT,
	CONF_PEER_TYPE_IPEER,
};

struct direct_peer {
	struct iv_avl_node	an;
	uint8_t			addr[16];
	char			*itfname;
};

struct conf_connect_entry {
	struct iv_avl_node	an;

	char			*name;
	char			*hostname;
	char			*port;
	uint8_t			fingerprint[NODE_ID_LEN];
	enum conf_peer_type	peer_type;
	char			*tunitf;
	int			cost;

	int			registered;
	struct tun_interface	tun;
	struct tconn_connect	tc;
	int			tconn_up;
	uint8_t			peerid[NODE_ID_LEN];
	struct direct_peer	dp;
	struct dgp_connect	dc;
};

struct conf_listening_socket {
	struct iv_avl_node		an;

	struct sockaddr_storage		listen_address;
	struct iv_avl_tree		listen_entries;

	int				registered;
	struct tconn_listen_socket	tls;
};

struct conf_listen_entry {
	struct iv_avl_node		an;

	char				*name;
	uint8_t				fingerprint[NODE_ID_LEN];
	enum conf_peer_type		peer_type;
	char				*tunitf;
	int				cost;
	int				conn_limit;

	int				registered;
	struct tconn_listen_entry	tle;
	int				num_connections;
	struct iv_list_head		connections;
};

struct conf *parse_config(const char *file);
void free_config(struct conf *conf);


#endif
