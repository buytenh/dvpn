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
#include <iv.h>
#include <iv_avl.h>
#include <iv_list.h>
#include <netinet/in.h>
#include <string.h>
#include "lsa_diff.h"
#include "lsa_path.h"
#include "lsa_peer.h"
#include "lsa_type.h"
#include "loc_rib.h"

static int
compare_ids(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
	const struct loc_rib_id *a;
	const struct loc_rib_id *b;

	a = iv_container_of(_a, struct loc_rib_id, an);
	b = iv_container_of(_b, struct loc_rib_id, an);

	return memcmp(a->id, b->id, NODE_ID_LEN);
}

static uint64_t lsa_get_version(const struct lsa *lsa)
{
	struct lsa_attr *attr;
	uint32_t *data;
	uint64_t version;

	attr = lsa_find_attr((struct lsa *)lsa, LSA_ATTR_TYPE_VERSION, NULL, 0);
	if (attr == NULL || !attr->attr_signed || attr->datalen != 8)
		return 0;

	data = lsa_attr_data(attr);

	version = ntohl(data[0]);
	version <<= 32;
	version |= ntohl(data[1]);

	return version;
}

static struct lsa *find_recent_lsa(struct loc_rib *rib, const uint8_t *id)
{
	struct loc_rib_id *rid;
	struct iv_avl_node *an;
	struct lsa *lsa;

	rid = loc_rib_find_id(rib, id);
	if (rid == NULL)
		return NULL;

	an = iv_avl_tree_max(&rid->lsas);
	if (an == NULL)
		return NULL;

	lsa = iv_container_of(an, struct loc_rib_lsa_ref, an)->lsa;
	if (lsa_get_version(lsa) < rid->highest_version_seen)
		return NULL;

	return lsa;
}

static uint32_t
lsa_path_cost(struct loc_rib *rib, struct loc_rib_id *rid, struct lsa *lsa)
{
	struct lsa_attr *pathattr;
	uint8_t *path;
	int pathlen;
	struct lsa *from;
	int traversing_transits;
	int cost;
	int i;

	if (lsa_get_version(lsa) < rid->highest_version_seen)
		return RIB_COST_INELIGIBLE;

	pathattr = lsa_find_attr(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (pathattr == NULL)
		abort();

	path = lsa_attr_data(pathattr);
	pathlen = pathattr->datalen;

	if ((pathlen % NODE_ID_LEN) != 0)
		abort();

	from = NULL;
	if (rib->myid != NULL) {
		from = find_recent_lsa(rib, rib->myid);
		if (from == NULL)
			return RIB_COST_UNREACHABLE;
	}

	traversing_transits = 1;
	cost = 0;
	for (i = 0; i < pathlen; i += NODE_ID_LEN) {
		struct lsa *to;
		struct lsa_peer_info forward;
		struct lsa_peer_info reverse;

		to = find_recent_lsa(rib, path + i);
		if (to == NULL)
			return RIB_COST_UNREACHABLE;

		if (i == 0 && from == NULL) {
			from = to;
			continue;
		}

		if (lsa_get_peer_info(&forward, from, to->id) < 0)
			return RIB_COST_UNREACHABLE;

		if (lsa_get_peer_info(&reverse, to, from->id) < 0)
			return RIB_COST_UNREACHABLE;

		if (traversing_transits) {
			if (!(forward.flags & LSA_PEER_FLAGS_TRANSIT))
				traversing_transits = 0;
			if (!(reverse.flags & LSA_PEER_FLAGS_CUSTOMER))
				traversing_transits = 0;
		} else {
			if (!(forward.flags & LSA_PEER_FLAGS_CUSTOMER))
				return RIB_COST_UNREACHABLE;
			if (!(reverse.flags & LSA_PEER_FLAGS_TRANSIT))
				return RIB_COST_UNREACHABLE;
		}

		cost += forward.metric;

		from = to;
	}

	return cost;
}

static int lsa_has_shorter_adv_path(struct lsa *a, struct lsa *b)
{
	struct lsa_attr *apath;

	apath = lsa_find_attr(a, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (apath == NULL)
		abort();

	if (b != NULL) {
		struct lsa_attr *bpath;

		bpath = lsa_find_attr(b, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
		if (bpath == NULL)
			abort();

		if (apath->datalen < bpath->datalen)
			return 1;
	}

	return 0;
}

static void recompute_rid(struct loc_rib *rib, struct loc_rib_id *rid)
{
	struct lsa *oldbest;
	uint32_t oldbestcost;
	struct lsa *best;
	uint32_t bestcost;
	struct iv_avl_node *an;
	struct iv_list_head *ilh;
	struct iv_list_head *ilh2;
	struct rib_listener *rl;

	oldbest = rid->best;
	oldbestcost = rid->bestcost;

	best = NULL;
	bestcost = RIB_COST_INELIGIBLE;

	iv_avl_tree_for_each (an, &rid->lsas) {
		struct loc_rib_lsa_ref *ref;
		uint32_t cost;

		ref = iv_container_of(an, struct loc_rib_lsa_ref, an);

		cost = lsa_path_cost(rib, rid, ref->lsa);
		ref->cost = cost;

		if (cost < bestcost) {
			best = ref->lsa;
			bestcost = cost;
		} else if (cost == bestcost &&
			   lsa_has_shorter_adv_path(ref->lsa, best)) {
			best = ref->lsa;
		}
	}

	if (oldbest == best && oldbestcost == bestcost)
		return;

	rid->best = lsa_get(best);
	rid->bestcost = bestcost;

	if (oldbest == NULL && best != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_add(rl->cookie, best, bestcost);
		}
	} else if (oldbest != NULL && best != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_mod(rl->cookie, oldbest, oldbestcost,
				    best, bestcost);
		}
	} else if (oldbest != NULL && best == NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_del(rl->cookie, oldbest, oldbestcost);
		}
	}

	lsa_put(oldbest);
}

static void recompute_rib(void *_rib)
{
	struct loc_rib *rib = _rib;
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &rib->ids) {
		struct loc_rib_id *rid;

		rid = iv_container_of(an, struct loc_rib_id, an);
		recompute_rid(rib, rid);
	}
}

void loc_rib_init(struct loc_rib *rib)
{
	INIT_IV_AVL_TREE(&rib->ids, compare_ids);

	IV_TASK_INIT(&rib->recompute);
	rib->recompute.cookie = rib;
	rib->recompute.handler = recompute_rib;

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

		lsa_put(rid->best);

		iv_avl_tree_delete(&rib->ids, &rid->an);
		free(rid);
	}

	if (iv_task_registered(&rib->recompute))
		iv_task_unregister(&rib->recompute);
}

struct loc_rib_id *loc_rib_find_id(struct loc_rib *rib, const uint8_t *id)
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

static int compare_lsas(const struct lsa *a, const struct lsa *b)
{
	uint64_t aver;
	uint64_t bver;

	aver = lsa_get_version(a);
	bver = lsa_get_version(b);
	if (aver < bver)
		return -1;
	if (aver > bver)
		return 1;

	if (a < b)
		return -1;
	if (a > b)
		return 1;

	return 0;
}

static int
compare_lsa_refs(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
	const struct lsa *a;
	const struct lsa *b;
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

static struct loc_rib_id *get_id(struct loc_rib *rib, const uint8_t *id)
{
	struct loc_rib_id *rid;

	rid = loc_rib_find_id(rib, id);
	if (rid != NULL)
		return rid;

	rid = malloc(sizeof(*rid));
	if (rid == NULL)
		abort();

	memcpy(rid->id, id, NODE_ID_LEN);
	rid->highest_version_seen = 0;
	INIT_IV_AVL_TREE(&rid->lsas, compare_lsa_refs);
	rid->best = NULL;
	rid->bestcost = RIB_COST_INELIGIBLE;

	iv_avl_tree_insert(&rib->ids, &rid->an);

	return rid;
}

void loc_rib_add_lsa(struct loc_rib *rib, struct lsa *lsa)
{
	struct loc_rib_id *rid;
	struct loc_rib_lsa_ref *ref;
	uint64_t ver;

	rid = get_id(rib, lsa->id);

	ref = malloc(sizeof(*ref));
	if (ref == NULL)
		abort();

	ref->lsa = lsa_get(lsa);
	if (iv_avl_tree_insert(&rid->lsas, &ref->an) < 0) {
		fprintf(stderr, "loc_rib_add_lsa: duplicate LSA inserted!\n");
		abort();
	}

	ver = lsa_get_version(lsa);
	if (rid->highest_version_seen < ver)
		rid->highest_version_seen = ver;

	if (!iv_task_registered(&rib->recompute))
		iv_task_register(&rib->recompute);
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

	lsa_put(old);

	if (!iv_task_registered(&rib->recompute))
		iv_task_register(&rib->recompute);
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

	lsa_put(lsa);
	free(ref);

	if (!iv_task_registered(&rib->recompute))
		iv_task_register(&rib->recompute);
}

void loc_rib_listener_register(struct loc_rib *rib, struct rib_listener *rl)
{
	iv_list_add_tail(&rl->list, &rib->listeners);
}

void loc_rib_listener_unregister(struct loc_rib *rib, struct rib_listener *rl)
{
	iv_list_del(&rl->list);
}
