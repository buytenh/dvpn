/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2016 Lennert Buytenhek
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

#ifndef __DGP_LISTEN_H
#define __DGP_LISTEN_H

#include <iv.h>
#include "loc_rib.h"
#include "dgp_reader.h"
#include "dgp_writer.h"

struct dgp_listen_socket {
	uint8_t			*myid;
	int			ifindex;
	struct loc_rib		*loc_rib;
	int			permit_readonly;

	struct iv_fd		listen_fd;
	struct iv_list_head	listen_entries;
	struct iv_list_head	readonly_conns;
};

int dgp_listen_socket_register(struct dgp_listen_socket *dls);
void dgp_listen_socket_unregister(struct dgp_listen_socket *dls);

struct dgp_listen_entry {
	struct dgp_listen_socket	*dls;
	uint8_t				*remoteid;

	struct iv_list_head		list;
	struct conn			*current;
};

void dgp_listen_entry_register(struct dgp_listen_entry *dle);
void dgp_listen_entry_unregister(struct dgp_listen_entry *dle);


#endif
