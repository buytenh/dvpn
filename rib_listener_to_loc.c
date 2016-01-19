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

#include <stdio.h>
#include <stdlib.h>
#include "loc_rib.h"
#include "rib_listener.h"
#include "rib_listener_to_loc.h"
#include "util.h"

static void lsa_add(void *cookie, struct lsa *a)
{
	struct rib_listener_to_loc *rl = cookie;

	loc_rib_add_lsa(rl->dest, a);
}

static void lsa_mod(void *cookie, struct lsa *a, struct lsa *b)
{
	struct rib_listener_to_loc *rl = cookie;

	loc_rib_mod_lsa(rl->dest, a, b);
}

static void lsa_del(void *cookie, struct lsa *a)
{
	struct rib_listener_to_loc *rl = cookie;

	loc_rib_del_lsa(rl->dest, a);
}

void rib_listener_to_loc_init(struct rib_listener_to_loc *rl)
{
	rl->rl.cookie = rl;
	rl->rl.lsa_add = lsa_add;
	rl->rl.lsa_mod = lsa_mod;
	rl->rl.lsa_del = lsa_del;
}

void rib_listener_to_loc_deinit(struct rib_listener_to_loc *rl)
{
}
