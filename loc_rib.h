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

#ifndef __LOC_RIB_H
#define __LOC_RIB_H

#include <iv.h>
#include <iv_avl.h>
#include <iv_list.h>
#include "lsa.h"
#include "rib_listener.h"

struct loc_rib {
	uint8_t			*myid;

	struct iv_avl_tree	ids;
	struct iv_task		recompute;
	struct iv_list_head	listeners;
};

struct loc_rib_id {
	struct iv_avl_node	an;
	uint8_t			id[NODE_ID_LEN];
	uint64_t		highest_version_seen;
	struct iv_avl_tree	lsas;
	struct lsa		*best;
	uint32_t		bestcost;
};

struct loc_rib_lsa_ref {
	struct iv_avl_node	an;
	struct lsa		*lsa;
	uint32_t		cost;
};

void loc_rib_init(struct loc_rib *rib);
void loc_rib_deinit(struct loc_rib *rib);
struct loc_rib_id *loc_rib_find_id(struct loc_rib *rib, uint8_t *id);
void loc_rib_add_lsa(struct loc_rib *rib, struct lsa *lsa);
void loc_rib_mod_lsa(struct loc_rib *rib, struct lsa *lsa, struct lsa *newlsa);
void loc_rib_del_lsa(struct loc_rib *rib, struct lsa *lsa);

void loc_rib_listener_register(struct loc_rib *rib, struct rib_listener *rl);
void loc_rib_listener_unregister(struct loc_rib *rib, struct rib_listener *rl);


#endif
