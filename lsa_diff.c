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

static void dummy_attr_add(void *cookie, struct lsa_attr *attr)
{
}

static void
dummy_attr_mod(void *cookie, struct lsa_attr *aattr, struct lsa_attr *battr)
{
}

static void dummy_attr_del(void *cookie, struct lsa_attr *attr)
{
}

int lsa_diff(struct lsa *a, struct lsa *b, void *cookie,
	     void (*attr_add)(void *, struct lsa_attr *),
	     void (*attr_mod)(void *, struct lsa_attr *, struct lsa_attr *),
	     void (*attr_del)(void *, struct lsa_attr *))
{
	struct iv_avl_node *anode;
	struct iv_avl_node *bnode;
	int diffs;

	if (attr_add == NULL)
		attr_add = dummy_attr_add;
	if (attr_mod == NULL)
		attr_mod = dummy_attr_mod;
	if (attr_del == NULL)
		attr_del = dummy_attr_del;

	if (a != NULL)
		anode = iv_avl_tree_min(&a->attrs);
	else
		anode = NULL;

	if (b != NULL)
		bnode = iv_avl_tree_min(&b->attrs);
	else
		bnode = NULL;

	diffs = 0;

	while (anode != NULL && bnode != NULL) {
		struct lsa_attr *aattr;
		struct lsa_attr *battr;
		int ret;

		aattr = iv_container_of(anode, struct lsa_attr, an);
		battr = iv_container_of(bnode, struct lsa_attr, an);

		ret = lsa_attr_compare_keys(aattr, battr);

		if (ret < 0) {
			diffs++;
			attr_del(cookie, aattr);

			anode = iv_avl_tree_next(anode);
		} else if (ret > 0) {
			diffs++;
			attr_add(cookie, battr);

			bnode = iv_avl_tree_next(bnode);
		} else {
			if (aattr->datalen != battr->datalen ||
			    memcmp(aattr->data, battr->data, aattr->datalen)) {
				diffs++;
				attr_mod(cookie, aattr, battr);
			}

			anode = iv_avl_tree_next(anode);
			bnode = iv_avl_tree_next(bnode);
		}
	}

	while (anode != NULL) {
		diffs++;
		attr_del(cookie, iv_container_of(anode, struct lsa_attr, an));

		anode = iv_avl_tree_next(anode);
	}

	while (bnode != NULL) {
		diffs++;
		attr_add(cookie, iv_container_of(bnode, struct lsa_attr, an));

		bnode = iv_avl_tree_next(bnode);
	}

	return diffs;
}
