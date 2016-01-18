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
#include "lsa_diff.h"
#include "lsa_path.h"
#include "lsa_type.h"
#include "loc_rib.h"

static int compare_ids(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct loc_rib_id *a;
	struct loc_rib_id *b;

	a = iv_container_of(_a, struct loc_rib_id, an);
	b = iv_container_of(_b, struct loc_rib_id, an);

	return memcmp(a->id, b->id, sizeof(a->id));
}

void loc_rib_init(struct loc_rib *rib)
{
	INIT_IV_AVL_TREE(&rib->ids, compare_ids);
	INIT_IV_LIST_HEAD(&rib->listeners);
}

void loc_rib_deinit(struct loc_rib *rib)
{
	struct iv_avl_node *an;

	while (!iv_avl_tree_empty(&rib->ids)) {
		struct loc_rib_id *rid;

                an = iv_avl_tree_min(&rib->ids);
		rid = iv_container_of(an, struct loc_rib_id, an);

		while (!iv_avl_tree_empty(&rid->lsas)) {
			struct loc_rib_lsa_ref *ref;

			an = iv_avl_tree_min(&rid->lsas);
			ref = iv_container_of(an, struct loc_rib_lsa_ref, an);

			iv_avl_tree_delete(&rid->lsas, &ref->an);
			lsa_put(ref->lsa);
			free(ref);
		}

		iv_avl_tree_delete(&rib->ids, &rid->an);
		free(rid);
	}
}

static struct loc_rib_id *find_id(struct loc_rib *rib, uint8_t *id)
{
	struct iv_avl_node *an;

	an = rib->ids.root;
	while (an != NULL) {
		struct loc_rib_id *rid;
		int ret;

		rid = iv_container_of(an, struct loc_rib_id, an);

		ret = memcmp(id, rid->id, sizeof(rid->id));
		if (ret == 0)
			return rid;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int compare_lsa_refs(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct loc_rib_lsa_ref *a;
	struct loc_rib_lsa_ref *b;

	a = iv_container_of(_a, struct loc_rib_lsa_ref, an);
	b = iv_container_of(_b, struct loc_rib_lsa_ref, an);

	return memcmp(&a->lsa, &b->lsa, sizeof(a->lsa));
}

static struct loc_rib_id *get_id(struct loc_rib *rib, uint8_t *id)
{
	struct loc_rib_id *rid;

	rid = find_id(rib, id);
	if (rid != NULL)
		return rid;

	rid = malloc(sizeof(*rid));
	if (rid == NULL)
		abort();

	memcpy(rid->id, id, 32);
	INIT_IV_AVL_TREE(&rid->lsas, compare_lsa_refs);
	rid->best = NULL;

	iv_avl_tree_insert(&rib->ids, &rid->an);

	return rid;
}

static int lsa_better(struct lsa *a, struct lsa *b)
{
	struct lsa_attr *aattr;
	struct lsa_attr *battr;

	aattr = lsa_attr_find(a, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (aattr == NULL)
		abort();

	battr = lsa_attr_find(b, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (battr == NULL)
		abort();

	if (aattr->datalen < battr->datalen)
		return 1;
	if (aattr->datalen > battr->datalen)
		return 0;

	return !!(memcmp(aattr->data, battr->data, aattr->datalen) < 0);
}

static void set_newbest(struct loc_rib *rib, struct loc_rib_id *rid,
			struct lsa *old, struct loc_rib_lsa_ref *new)
{
	struct iv_list_head *ilh;
	struct iv_list_head *ilh2;
	struct rib_listener *rl;

	if (old == NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_add(rl->cookie, new->lsa);
		}
	} else if (old != NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_mod(rl->cookie, old, new->lsa);
		}
	} else if (old != NULL && new == NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_del(rl->cookie, old);
		}
	}

	rid->best = new;
}

void loc_rib_add_lsa(struct loc_rib *rib, struct lsa *lsa)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;

	rid = get_id(rib, lsa->id);

	ref = malloc(sizeof(*ref));
	if (ref == NULL)
		abort();

	ref->lsa = lsa_get(lsa);
	iv_avl_tree_insert(&rid->lsas, &ref->an);

	if (rid->best == NULL || lsa_better(lsa, rid->best->lsa))
		set_newbest(rib, rid, rid->best ? rid->best->lsa : NULL, ref);
}

static struct loc_rib_lsa_ref *
find_lsa_ref(struct loc_rib_id *rid, struct lsa *lsa)
{
	struct iv_avl_node *an;

	an = rid->lsas.root;
	while (an != NULL) {
		struct loc_rib_lsa_ref *ref;
		int ret;

		ref = iv_container_of(an, struct loc_rib_lsa_ref, an);

		ret = memcmp(&lsa, &ref->lsa, sizeof(ref->lsa));
		if (ret == 0)
			return ref;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static void recompute_best_lsa(struct loc_rib *rib, struct loc_rib_id *rid,
			       struct lsa *old)
{
	struct loc_rib_lsa_ref *best;
	struct iv_avl_node *an;

	best = NULL;

	iv_avl_tree_for_each (an, &rid->lsas) {
		struct loc_rib_lsa_ref *ref;

		ref = iv_container_of(an, struct loc_rib_lsa_ref, an);

		if (best == NULL || lsa_better(ref->lsa, best->lsa))
			best = ref;
	}

	set_newbest(rib, rid, old, best);
}

void loc_rib_mod_lsa(struct loc_rib *rib, struct lsa *lsa, struct lsa *newlsa)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;

	rid = find_id(rib, lsa->id);
	if (rid == NULL)
		abort();

	ref = find_lsa_ref(rid, lsa);
	if (ref == NULL)
		abort();

	iv_avl_tree_delete(&rid->lsas, &ref->an);
	ref->lsa = lsa_get(newlsa);
	iv_avl_tree_insert(&rid->lsas, &ref->an);

	if (rid->best == ref) {
		recompute_best_lsa(rib, rid, lsa);
	} else if (rid->best == NULL || lsa_better(newlsa, rid->best->lsa)) {
		set_newbest(rib, rid, rid->best ? rid->best->lsa : NULL, ref);
	}

	lsa_put(lsa);
}

void loc_rib_del_lsa(struct loc_rib *rib, struct lsa *lsa)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;

	rid = find_id(rib, lsa->id);
	if (rid == NULL)
		abort();

	ref = find_lsa_ref(rid, lsa);
	if (ref == NULL)
		abort();

	iv_avl_tree_delete(&rid->lsas, &ref->an);

	if (rid->best == ref)
		recompute_best_lsa(rib, rid, lsa);

	lsa_put(lsa);
	free(ref);

	if (iv_avl_tree_empty(&rid->lsas)) {
		iv_avl_tree_delete(&rib->ids, &rid->an);
		free(rid);
	}
}

void loc_rib_listener_register(struct loc_rib *rib, struct rib_listener *rl)
{
	iv_list_add_tail(&rl->list, &rib->listeners);
}

void loc_rib_listener_unregister(struct loc_rib *rib, struct rib_listener *rl)
{
	iv_list_del(&rl->list);
}
