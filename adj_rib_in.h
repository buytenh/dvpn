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

#ifndef __ADJ_RIB_IN_H
#define __ADJ_RIB_IN_H

#include <iv_avl.h>
#include <iv_list.h>
#include "lsa.h"
#include "rib_listener.h"

#define ADJ_RIB_IN_MAX_BYTES	1048576
#define LSA_MAX_BYTES		32768

struct adj_rib_in {
	uint8_t			*myid;
	uint8_t			*remoteid;

	struct iv_avl_tree	lsas;
	int			size;
	struct iv_list_head	listeners;
};

void adj_rib_in_init(struct adj_rib_in *rib);
int adj_rib_in_add_lsa(struct adj_rib_in *rib, struct lsa *lsa);
void adj_rib_in_flush(struct adj_rib_in *rib);

void adj_rib_in_listener_register(struct adj_rib_in *rib,
				  struct rib_listener *rl);
void adj_rib_in_listener_unregister(struct adj_rib_in *rib,
				    struct rib_listener *rl);


#endif
