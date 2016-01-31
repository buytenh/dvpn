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
#include "lsa_path.h"
#include "lsa_serialise.h"
#include "lsa_type.h"

#define KEEPALIVE_INTERVAL	10

static struct lsa *map(struct dgp_writer *dw, struct lsa *lsa)
{
	struct lsa_attr *attr;

	if (lsa == NULL)
		return NULL;

	attr = lsa_attr_find(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		return NULL;

	if (dw->remoteid != NULL && lsa_path_contains(attr, dw->remoteid))
		return NULL;

	if (lsa->size + 2 * NODE_ID_LEN > LSA_MAX_SIZE)
		return NULL;

	return lsa;
}

static int
dgp_writer_output_lsa(struct dgp_writer *dw, struct lsa *old, struct lsa *new)
{
	uint8_t buf[LSA_MAX_SIZE];
	int len;
	struct lsa dummy;
	struct lsa *lsa;

	lsa = map(dw, new);
	if (lsa == NULL) {
		if (map(dw, old) == NULL)
			return 0;

		dummy.size = 2 + NODE_ID_LEN;
		memcpy(&dummy.id, old->id, NODE_ID_LEN);
		INIT_IV_AVL_TREE(&dummy.attrs, NULL);

		lsa = &dummy;
	}

	len = lsa_serialise(buf, sizeof(buf), lsa, dw->myid);
	if (len < 0)
		abort();

	if (write(dw->fd, buf, len) != len) {
		dw->io_error(dw->cookie);
		return 1;
	}

	iv_timer_unregister(&dw->keepalive_timer);
	iv_validate_now();
	dw->keepalive_timer.expires = iv_now;
	dw->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&dw->keepalive_timer);

	return 0;
}

static void dgp_writer_lsa_add(void *_dw, struct lsa *lsa)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, NULL, lsa);
}

static void dgp_writer_lsa_mod(void *_dw, struct lsa *old, struct lsa *new)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, old, new);
}

static void dgp_writer_lsa_del(void *_dw, struct lsa *lsa)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, lsa, NULL);
}

static int dgp_writer_rib_dump(struct dgp_writer *dw)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &dw->rib->ids) {
		struct loc_rib_id *rid;

		rid = iv_container_of(an, struct loc_rib_id, an);
		if (dgp_writer_output_lsa(dw, NULL, rid->best))
			return 1;
	}

	return 0;
}

static void dgp_writer_send_keepalive(struct dgp_writer *dw)
{
	uint8_t buf[2];

	buf[0] = 0x00;
	buf[1] = 0x00;

	if (write(dw->fd, buf, 2) != 2)
		dw->io_error(dw->cookie);
}

static void dgp_writer_keepalive_timer(void *_dw)
{
	struct dgp_writer *dw = _dw;

	iv_validate_now();
	dw->keepalive_timer.expires = iv_now;
	dw->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&dw->keepalive_timer);

	dgp_writer_send_keepalive(dw);
}

void dgp_writer_register(struct dgp_writer *dw)
{
	dw->from_loc.cookie = dw;
	dw->from_loc.lsa_add = dgp_writer_lsa_add;
	dw->from_loc.lsa_mod = dgp_writer_lsa_mod;
	dw->from_loc.lsa_del = dgp_writer_lsa_del;
	loc_rib_listener_register(dw->rib, &dw->from_loc);

	IV_TIMER_INIT(&dw->keepalive_timer);
	iv_validate_now();
	dw->keepalive_timer.expires = iv_now;
	dw->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	dw->keepalive_timer.cookie = dw;
	dw->keepalive_timer.handler = dgp_writer_keepalive_timer;
	iv_timer_register(&dw->keepalive_timer);

	if (!dgp_writer_rib_dump(dw))
		dgp_writer_send_keepalive(dw);
}

void dgp_writer_unregister(struct dgp_writer *dw)
{
	loc_rib_listener_unregister(dw->rib, &dw->from_loc);
	iv_timer_unregister(&dw->keepalive_timer);
}
