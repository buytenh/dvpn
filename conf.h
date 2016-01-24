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

#include <iv_list.h>
#include <stdint.h>
#include <sys/socket.h>
#include "dvpn.h"
#include "listen.h"
#include "tconn_connect.h"
#include "util.h"

struct conf
{
	char			*private_key;
	char			*node_name;

	struct iv_list_head	connect_entries;
	struct iv_list_head	listening_sockets;
};

struct conf_connect_entry
{
	struct iv_list_head	list;

	char			*name;
	char			*hostname;
	char			*port;
	uint8_t			fingerprint[NODE_ID_LEN];
	enum peer_type		peer_type;
	char			*tunitf;

	int			registered;
	struct tconn_connect	tc;
	struct peer		peer;
};

struct conf_listening_socket
{
	struct iv_list_head	list;

	struct sockaddr_storage	listen_address;
	struct iv_list_head	listen_entries;

	int			registered;
	struct listening_socket	ls;
};

struct conf_listen_entry
{
	struct iv_list_head	list;

	char			*name;
	uint8_t			fingerprint[NODE_ID_LEN];
	enum peer_type		peer_type;
	char			*tunitf;

	int			registered;
	struct listen_entry	le;
	struct peer		peer;
};

struct conf *parse_config(const char *file);
void free_config(struct conf *conf);


#endif
