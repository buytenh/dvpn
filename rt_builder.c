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
#include "loc_rib.h"
#include "lsa_type.h"
#include "rt_builder.h"
#include "util.h"

static struct lsa *map(struct rt_builder *rb, struct lsa *lsa, uint32_t cost)
{
	struct lsa_attr *attr;

	if (cost == RIB_COST_INELIGIBLE)
		abort();

	if (cost == RIB_COST_UNREACHABLE)
		return NULL;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		abort();

	if (attr->datalen == 0)
		return NULL;

	if (rb->myid != NULL && attr->datalen == NODE_ID_LEN &&
	    !memcmp(lsa_attr_data(attr), rb->myid, NODE_ID_LEN)) {
		return NULL;
	}

	return lsa;
}

static uint8_t *getnh(struct rt_builder *rb, struct lsa *lsa, uint8_t *addr)
{
	struct lsa_attr *attr;
	uint8_t *adv_path;
	int len;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		abort();

	adv_path = lsa_attr_data(attr);
	len = attr->datalen;

	if (rb->myid != NULL && len >= NODE_ID_LEN &&
	    !memcmp(adv_path, rb->myid, NODE_ID_LEN)) {
		adv_path += NODE_ID_LEN;
		len -= NODE_ID_LEN;
	}

	if (len == 0)
		abort();

	if (len == NODE_ID_LEN)
		return NULL;

	v6_global_addr_from_key_id(addr, adv_path);

	return addr;
}

static void rt_add(struct rt_builder *rb, struct lsa *lsa)
{
	uint8_t dest[16];
	uint8_t nh[16];

	v6_global_addr_from_key_id(dest, lsa->id);

	rb->rt_add(rb->cookie, dest, getnh(rb, lsa, nh));
}

static void rt_mod(struct rt_builder *rb, struct lsa *old, struct lsa *new)
{
	uint8_t dest[16];
	uint8_t nhold[16];
	uint8_t nhnew[16];

	v6_global_addr_from_key_id(dest, new->id);

	rb->rt_mod(rb->cookie, dest, getnh(rb, old, nhold),
		   getnh(rb, new, nhnew));
}

static void rt_del(struct rt_builder *rb, struct lsa *lsa)
{
	uint8_t dest[16];
	uint8_t nh[16];

	v6_global_addr_from_key_id(dest, lsa->id);

	rb->rt_del(rb->cookie, dest, getnh(rb, lsa, nh));
}

static void lsa_add(void *_rb, struct lsa *a, uint32_t cost)
{
	struct rt_builder *rb = _rb;

	a = map(rb, a, cost);
	if (a != NULL)
		rt_add(rb, a);
}

static void lsa_mod(void *_rb, struct lsa *a, uint32_t acost,
		    struct lsa *b, uint32_t bcost)
{
	struct rt_builder *rb = _rb;

	a = map(rb, a, acost);
	b = map(rb, b, bcost);

	if (a == NULL && b != NULL)
		rt_add(rb, b);
	else if (a != NULL && b != NULL)
		rt_mod(rb, a, b);
	else if (a != NULL && b == NULL)
		rt_del(rb, a);
}

static void lsa_del(void *_rb, struct lsa *a, uint32_t cost)
{
	struct rt_builder *rb = _rb;

	a = map(rb, a, cost);
	if (a != NULL)
		rt_del(rb, a);
}

void rt_builder_init(struct rt_builder *rb)
{
	rb->rl.cookie = rb;
	rb->rl.lsa_add = lsa_add;
	rb->rl.lsa_mod = lsa_mod;
	rb->rl.lsa_del = lsa_del;
	loc_rib_listener_register(rb->rib, &rb->rl);
}

void rt_builder_deinit(struct rt_builder *rb)
{
	loc_rib_listener_unregister(rb->rib, &rb->rl);
}
