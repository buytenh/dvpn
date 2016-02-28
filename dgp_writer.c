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
#include <netinet/tcp.h>
#include <string.h>
#include "dgp_writer.h"
#include "lsa_path.h"
#include "lsa_serialise.h"
#include "lsa_type.h"
#include "util.h"

#define KEEPALIVE_INTERVAL	10

static struct lsa *map(struct dgp_writer *dw, struct lsa *lsa)
{
	struct lsa_attr *attr;

	if (lsa == NULL)
		return NULL;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		return NULL;

	if (dw->remoteid != NULL && lsa_path_contains(attr, dw->remoteid))
		return NULL;

	return lsa;
}

static int
dgp_writer_output_lsa(struct dgp_writer *dw, struct lsa *old, struct lsa *new)
{
	size_t serlen;
	size_t buflen;
	uint8_t *buf;
	size_t len;
	struct lsa dummy;
	struct lsa *lsa;

	lsa = map(dw, new);
	if (lsa == NULL) {
		if (map(dw, old) == NULL)
			return 0;

		memcpy(&dummy.id, old->id, NODE_ID_LEN);
		INIT_IV_AVL_TREE(&dummy.root.attrs, NULL);

		lsa = &dummy;
	}

	serlen = lsa_serialise_length(lsa, 0, dw->myid);
	if (serlen > 65536 - 128)
		abort();

	buflen = serlen + 128;
	buf = alloca(buflen);

	len = lsa_serialise(buf, buflen, serlen, lsa, 0, dw->myid);
	if (len > buflen)
		abort();

	if (write(dw->fd, buf, len) != len) {
		dw->io_error(dw->cookie);
		return 1;
	}

	iv_timer_unregister(&dw->keepalive_timer);
	iv_validate_now();
	dw->keepalive_timer.expires = iv_now;
	timespec_add_ms(&dw->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
	iv_timer_register(&dw->keepalive_timer);

	return 0;
}

static void dgp_writer_lsa_add(void *_dw, struct lsa *lsa, uint32_t cost)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, NULL, lsa);
}

static void dgp_writer_lsa_mod(void *_dw, struct lsa *old, uint32_t oldcost,
			       struct lsa *new, uint32_t newcost)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, old, new);
}

static void dgp_writer_lsa_del(void *_dw, struct lsa *lsa, uint32_t cost)
{
	struct dgp_writer *dw = _dw;

	dgp_writer_output_lsa(dw, lsa, NULL);
}

static void cork_fd(int fd, int state)
{
	if (setsockopt(fd, SOL_TCP, TCP_CORK, &state, sizeof(state)) < 0) {
		perror("setsockopt(SOL_TCP, TCP_CORK)");
		abort();
	}
}

static int dgp_writer_send_keepalive(struct dgp_writer *dw)
{
	if (write(dw->fd, "", 1) != 1) {
		dw->io_error(dw->cookie);
		return 1;
	}

	return 0;
}

static void dgp_writer_rib_dump(struct dgp_writer *dw)
{
	struct iv_avl_node *an;

	if (iv_avl_tree_empty(&dw->rib->ids)) {
		dgp_writer_send_keepalive(dw);
		return;
	}

	cork_fd(dw->fd, 1);

	iv_avl_tree_for_each (an, &dw->rib->ids) {
		struct loc_rib_id *rid;

		rid = iv_container_of(an, struct loc_rib_id, an);
		if (rid->best == NULL)
			continue;

		if (dgp_writer_output_lsa(dw, NULL, rid->best))
			return;
	}

	if (dgp_writer_send_keepalive(dw))
		return;

	cork_fd(dw->fd, 0);
}

static void dgp_writer_keepalive_timer(void *_dw)
{
	struct dgp_writer *dw = _dw;

	iv_validate_now();
	dw->keepalive_timer.expires = iv_now;
	timespec_add_ms(&dw->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
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
	timespec_add_ms(&dw->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
	dw->keepalive_timer.cookie = dw;
	dw->keepalive_timer.handler = dgp_writer_keepalive_timer;
	iv_timer_register(&dw->keepalive_timer);

	dgp_writer_rib_dump(dw);
}

void dgp_writer_unregister(struct dgp_writer *dw)
{
	loc_rib_listener_unregister(dw->rib, &dw->from_loc);
	iv_timer_unregister(&dw->keepalive_timer);
}
