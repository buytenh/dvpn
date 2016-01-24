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

#ifndef __ADJ_RIB_H
#define __ADJ_RIB_H

#include <iv_avl.h>
#include <iv_list.h>
#include "lsa.h"
#include "rib_listener.h"

#define ADJ_RIB_MAX_SIZE	1048576

struct adj_rib {
	uint8_t			myid[NODE_ID_LEN];
	uint8_t			remoteid[NODE_ID_LEN];

	struct iv_avl_tree	lsas;
	int			size;
	struct iv_list_head	listeners;
};

void adj_rib_init(struct adj_rib *rib);
int adj_rib_add_lsa(struct adj_rib *rib, struct lsa *lsa);
void adj_rib_flush(struct adj_rib *rib);

void adj_rib_listener_register(struct adj_rib *rib, struct rib_listener *rl);
void adj_rib_listener_unregister(struct adj_rib *rib, struct rib_listener *rl);


#endif
