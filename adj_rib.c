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
#include <iv_avl.h>
#include <iv_list.h>
#include <string.h>
#include "adj_rib.h"
#include "lsa_diff.h"
#include "lsa_path.h"
#include "lsa_type.h"

struct adj_rib_lsa_ref {
	struct iv_avl_node	an;
	struct lsa		*lsa;
};

static int compare_refs(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct adj_rib_lsa_ref *a;
	struct adj_rib_lsa_ref *b;

	a = iv_container_of(_a, struct adj_rib_lsa_ref, an);
	b = iv_container_of(_b, struct adj_rib_lsa_ref, an);

	return memcmp(a->lsa->id, b->lsa->id, NODE_ID_LEN);
}

void adj_rib_init(struct adj_rib *rib)
{
	INIT_IV_AVL_TREE(&rib->lsas, compare_refs);
	INIT_IV_LIST_HEAD(&rib->listeners);
}

static struct adj_rib_lsa_ref *
adj_rib_find_ref(struct adj_rib *rib, uint8_t *id)
{
	struct iv_avl_node *an;

	an = rib->lsas.root;
	while (an != NULL) {
		struct adj_rib_lsa_ref *ref;
		int ret;

		ref = iv_container_of(an, struct adj_rib_lsa_ref, an);

		ret = memcmp(id, ref->lsa->id, NODE_ID_LEN);
		if (ret == 0)
			return ref;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static struct lsa *map(struct adj_rib *rib, struct lsa *lsa)
{
	struct lsa_attr *attr;

	if (lsa == NULL)
		return NULL;

	attr = lsa_attr_find(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		return NULL;

	if (attr->datalen < NODE_ID_LEN ||
	    memcmp(rib->remoteid, lsa_attr_data(attr), NODE_ID_LEN))
		return NULL;

	if (lsa_path_contains(attr, rib->myid))
		return NULL;

	return lsa;
}

static void notify(struct adj_rib *rib, struct lsa *old, struct lsa *new)
{
	struct iv_list_head *ilh;
	struct iv_list_head *ilh2;
	struct rib_listener *rl;

	old = map(rib, old);
	new = map(rib, new);

	if (old == NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_add(rl->cookie, new);
		}
	} else if (old != NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_mod(rl->cookie, old, new);
		}
	} else if (old != NULL && new == NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_del(rl->cookie, old);
		}
	}
}

void adj_rib_add_lsa(struct adj_rib *rib, struct lsa *lsa)
{
	struct adj_rib_lsa_ref *ref;

	ref = adj_rib_find_ref(rib, lsa->id);

	if (iv_avl_tree_empty(&lsa->attrs)) {
		if (ref == NULL) {
			fprintf(stderr, "error!\n");
			return;
		}

		notify(rib, ref->lsa, NULL);

		iv_avl_tree_delete(&rib->lsas, &ref->an);
		lsa_put(ref->lsa);
		free(ref);
	} else if (ref == NULL) {
		notify(rib, NULL, lsa);

		ref = malloc(sizeof(*ref));
		if (ref == NULL)
			abort();

		ref->lsa = lsa_get(lsa);
		iv_avl_tree_insert(&rib->lsas, &ref->an);
	} else if (lsa_diff(ref->lsa, lsa, NULL, NULL, NULL, NULL)) {
		notify(rib, ref->lsa, lsa);

		lsa_put(ref->lsa);
		ref->lsa = lsa_get(lsa);
	}
}

void adj_rib_flush(struct adj_rib *rib)
{
	while (rib->lsas.root != NULL) {
		struct adj_rib_lsa_ref *ref;

		ref = iv_container_of(rib->lsas.root,
				      struct adj_rib_lsa_ref, an);

		notify(rib, ref->lsa, NULL);

		iv_avl_tree_delete(&rib->lsas, &ref->an);
		lsa_put(ref->lsa);
		free(ref);
	}
}

void adj_rib_listener_register(struct adj_rib *rib, struct rib_listener *rl)
{
	iv_list_add_tail(&rl->list, &rib->listeners);
}

void adj_rib_listener_unregister(struct adj_rib *rib, struct rib_listener *rl)
{
	iv_list_del(&rl->list);
}
