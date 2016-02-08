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

	return memcmp(a->id, b->id, NODE_ID_LEN);
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

struct loc_rib_id *loc_rib_find_id(struct loc_rib *rib, uint8_t *id)
{
	struct iv_avl_node *an;

	an = rib->ids.root;
	while (an != NULL) {
		struct loc_rib_id *rid;
		int ret;

		rid = iv_container_of(an, struct loc_rib_id, an);

		ret = memcmp(id, rid->id, NODE_ID_LEN);
		if (ret == 0)
			return rid;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static uint64_t lsa_get_version(struct lsa *lsa)
{
	struct lsa_attr *attr;
	uint32_t *data;
	uint64_t version;

	attr = lsa_attr_find(lsa, LSA_ATTR_TYPE_VERSION, NULL, 0);
	if (attr == NULL || attr->datalen != 8)
		return 0;

	data = lsa_attr_data(attr);

	version = ntohl(data[0]);
	version <<= 32;
	version |= ntohl(data[1]);

	return version;
}

static int compare_lsas(struct lsa *a, struct lsa *b)
{
	uint64_t aver;
	uint64_t bver;
	struct lsa_attr *aattr;
	struct lsa_attr *battr;
	int ret;

	aver = lsa_get_version(a);
	bver = lsa_get_version(b);
	if (aver < bver)
		return -1;
	if (aver > bver)
		return 1;

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

	ret = memcmp(lsa_attr_data(aattr), lsa_attr_data(battr),
		     aattr->datalen);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	return 0;
}

static int compare_lsa_refs(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct lsa *a;
	struct lsa *b;
	int ret;

	a = iv_container_of(_a, struct loc_rib_lsa_ref, an)->lsa;
	b = iv_container_of(_b, struct loc_rib_lsa_ref, an)->lsa;

	ret = compare_lsas(a, b);
	if (ret == 0) {
		fprintf(stderr, "compare_lsa_refs: found equal LSAs!\n");
		abort();
	}

	return ret;
}

static struct loc_rib_id *get_id(struct loc_rib *rib, uint8_t *id)
{
	struct loc_rib_id *rid;

	rid = loc_rib_find_id(rib, id);
	if (rid != NULL)
		return rid;

	rid = malloc(sizeof(*rid));
	if (rid == NULL)
		abort();

	memcpy(rid->id, id, NODE_ID_LEN);
	INIT_IV_AVL_TREE(&rid->lsas, compare_lsa_refs);
	rid->highest_version_seen = 0;
	rid->best = NULL;

	iv_avl_tree_insert(&rib->ids, &rid->an);

	return rid;
}

static void recompute_best_lsa(struct loc_rib *rib, struct loc_rib_id *rid)
{
	struct lsa *oldbest;
	struct lsa *best;
	struct iv_avl_node *an;
	struct iv_list_head *ilh;
	struct iv_list_head *ilh2;
	struct rib_listener *rl;

	oldbest = rid->best;

	best = NULL;

	an = iv_avl_tree_max(&rid->lsas);
	if (an != NULL) {
		best = iv_container_of(an, struct loc_rib_lsa_ref, an)->lsa;
		if (lsa_get_version(best) < rid->highest_version_seen)
			best = NULL;
	}

	if (best == oldbest)
		return;

	if (best != NULL)
		rid->highest_version_seen = lsa_get_version(best);

	rid->best = best;

	if (oldbest == NULL && best != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_add(rl->cookie, best);
		}
	} else if (oldbest != NULL && best != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_mod(rl->cookie, oldbest, best);
		}
	} else if (oldbest != NULL && best == NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_del(rl->cookie, oldbest);
		}
	}
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
	if (iv_avl_tree_insert(&rid->lsas, &ref->an) < 0) {
		fprintf(stderr, "loc_rib_add_lsa: duplicate LSA inserted!\n");
		abort();
	}

	if (iv_avl_tree_next(&ref->an) == NULL)
		recompute_best_lsa(rib, rid);
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

		ret = compare_lsas(lsa, ref->lsa);
		if (ret == 0)
			return ref;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

void loc_rib_mod_lsa(struct loc_rib *rib, struct lsa *old, struct lsa *new)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;

	rid = loc_rib_find_id(rib, old->id);
	if (rid == NULL)
		abort();

	ref = find_lsa_ref(rid, old);
	if (ref == NULL)
		abort();

	iv_avl_tree_delete(&rid->lsas, &ref->an);
	ref->lsa = lsa_get(new);
	iv_avl_tree_insert(&rid->lsas, &ref->an);

	if (rid->best == old || iv_avl_tree_next(&ref->an) == NULL)
		recompute_best_lsa(rib, rid);

	lsa_put(old);
}

void loc_rib_del_lsa(struct loc_rib *rib, struct lsa *lsa)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;

	rid = loc_rib_find_id(rib, lsa->id);
	if (rid == NULL)
		abort();

	ref = find_lsa_ref(rid, lsa);
	if (ref == NULL)
		abort();

	iv_avl_tree_delete(&rid->lsas, &ref->an);

	if (rid->best == lsa)
		recompute_best_lsa(rib, rid);

	lsa_put(lsa);
	free(ref);

	if (iv_avl_tree_empty(&rid->lsas) && !rid->highest_version_seen) {
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
