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
#include <iv_list.h>
#include <string.h>
#include "lsa.h"
#include "lsa_diff.h"
#include "lsa_serialise.h"
#include "util.h"

struct lsa_diff_request {
	int	diffs;
	void	*cookie;
	void	(*attr_add)(void *, struct lsa_attr *);
	void	(*attr_mod)(void *, struct lsa_attr *, struct lsa_attr *);
	void	(*attr_del)(void *, struct lsa_attr *);
};

static void dummy_attr_add(void *cookie, struct lsa_attr *attr)
{
}

static void dummy_attr_del(void *cookie, struct lsa_attr *attr)
{
}

static void add(void *_req, struct iv_avl_node *_a)
{
	struct lsa_diff_request *req = _req;
	struct lsa_attr *a;

	a = iv_container_of(_a, struct lsa_attr, an);

	req->diffs++;
	req->attr_add(req->cookie, a);
}

static int attr_cmp(struct lsa_attr *a, struct lsa_attr *b)
{
	if (a->data_is_attr_set != b->data_is_attr_set)
		return 1;

	if (!a->data_is_attr_set) {
		if (a->datalen != b->datalen)
			return 1;

		return memcmp(lsa_attr_data(a), lsa_attr_data(b), a->datalen);
	} else {
		size_t alen;
		size_t blen;
		uint8_t *abuf;
		uint8_t *bbuf;

		alen = lsa_attr_serialise_length(a);
		blen = lsa_attr_serialise_length(b);
		if (alen != blen)
			return 1;

		if (alen > 65536 - 16)
			abort();

		abuf = alloca(alen + 16);
		lsa_attr_serialise(abuf, alen + 16, a);

		bbuf = alloca(blen + 16);
		lsa_attr_serialise(bbuf, blen + 16, b);

		return memcmp(abuf, bbuf, alen);
	}
}

static void mod(void *_req, struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct lsa_diff_request *req = _req;
	struct lsa_attr *a;
	struct lsa_attr *b;

	a = iv_container_of(_a, struct lsa_attr, an);
	b = iv_container_of(_b, struct lsa_attr, an);

	if (attr_cmp(a, b)) {
		req->diffs++;

		if (req->attr_mod != NULL) {
			req->attr_mod(req->cookie, a, b);
		} else {
			req->attr_del(req->cookie, a);
			req->attr_add(req->cookie, b);
		}
	}
}

static void del(void *_req, struct iv_avl_node *_a)
{
	struct lsa_diff_request *req = _req;
	struct lsa_attr *a;

	a = iv_container_of(_a, struct lsa_attr, an);

	req->diffs++;
	req->attr_del(req->cookie, a);
}

int lsa_diff(struct lsa *_a, struct lsa *_b, void *cookie,
	     void (*attr_add)(void *, struct lsa_attr *),
	     void (*attr_mod)(void *, struct lsa_attr *, struct lsa_attr *),
	     void (*attr_del)(void *, struct lsa_attr *))
{
	struct lsa_diff_request req;
	struct iv_avl_tree *a;
	struct iv_avl_tree *b;

	req.diffs = 0;
	req.cookie = cookie;
	req.attr_add = attr_add ? : dummy_attr_add;
	req.attr_mod = attr_mod;
	req.attr_del = attr_del ? : dummy_attr_del;

	a = (_a != NULL) ? &_a->root.attrs : NULL;
	b = (_b != NULL) ? &_b->root.attrs : NULL;

	avl_diff(a, b, &req, add, mod, del);

	return req.diffs;
}
