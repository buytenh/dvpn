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
#include <string.h>
#include "dgp_writer.h"
#include "lsa_serialise.h"

static int dgp_writer_output_lsa(struct dgp_writer *dw, struct lsa *lsa)
{
	uint8_t buf[LSA_MAX_SIZE];
	int len;

	len = lsa_serialise(buf, sizeof(buf), lsa, NULL);
	if (len < 0)
		abort();

	if (write(dw->fd, buf, len) != len) {
		dw->io_error(dw->cookie);
		return 1;
	}

	return 0;
}

static void dgp_writer_lsa_add(void *_dw, struct lsa *lsa)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, lsa);
}

static void dgp_writer_lsa_mod(void *_dw, struct lsa *old, struct lsa *new)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, new);
}

static void dgp_writer_lsa_del(void *_dw, struct lsa *lsa)
{
	struct dgp_writer *dw = _dw;
	struct lsa dummy;

	dummy.size = 2 + NODE_ID_LEN;
	memcpy(&dummy.id, lsa->id, NODE_ID_LEN);
	INIT_IV_AVL_TREE(&dummy.attrs, NULL);

	dgp_writer_output_lsa(dw, &dummy);
}

static void dgp_writer_rib_dump(struct dgp_writer *dw)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &dw->rib->ids) {
		struct loc_rib_id *rid;

		rid = iv_container_of(an, struct loc_rib_id, an);
		if (dgp_writer_output_lsa(dw, rid->best))
			break;
	}
}

void dgp_writer_register(struct dgp_writer *dw)
{
	dw->from_loc.cookie = dw;
	dw->from_loc.lsa_add = dgp_writer_lsa_add;
	dw->from_loc.lsa_mod = dgp_writer_lsa_mod;
	dw->from_loc.lsa_del = dgp_writer_lsa_del;
	loc_rib_listener_register(dw->rib, &dw->from_loc);

	dgp_writer_rib_dump(dw);
}

void dgp_writer_unregister(struct dgp_writer *dw)
{
	loc_rib_listener_unregister(dw->rib, &dw->from_loc);
}
