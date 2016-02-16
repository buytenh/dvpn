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
#include "cspf.h"
#include "loc_rib.h"
#include "lsa_diff.h"
#include "lsa_type.h"
#include "rt_builder.h"

struct node {
	struct iv_avl_node	an;
	uint8_t			id[NODE_ID_LEN];
	int			refcount;
	struct cspf_node	node;
	struct iv_avl_tree	edges;
};

struct edge {
	struct iv_avl_node	an;
	struct node		*to;
	int			metric;
	enum peer_type		to_type;
	struct cspf_edge	edge;
};

static void recompute_rtable(struct rt_builder *rb);

static int compare_nodes(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct node *a = iv_container_of(_a, struct node, an);
	struct node *b = iv_container_of(_b, struct node, an);

	return memcmp(a->id, b->id, NODE_ID_LEN);
}

static struct node *find_node(struct rt_builder *rb, uint8_t *id)
{
	struct iv_avl_node *an;

	an = rb->nodes.root;
	while (an != NULL) {
		struct node *node;
		int ret;

		node = iv_container_of(an, struct node, an);

		ret = memcmp(id, node->id, NODE_ID_LEN);
		if (ret == 0)
			return node;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int compare_edges(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct edge *a = iv_container_of(_a, struct edge, an);
	struct edge *b = iv_container_of(_b, struct edge, an);

	return memcmp(a->to->id, b->to->id, NODE_ID_LEN);
}

static struct node *get_node(struct rt_builder *rb, uint8_t *id)
{
	struct node *node;

	node = find_node(rb, id);
	if (node != NULL) {
		node->refcount++;
		return node;
	}

	node = malloc(sizeof(*node));
	if (node == NULL)
		abort();

	memcpy(node->id, id, NODE_ID_LEN);
	node->refcount = 1;

	node->node.id = node->id;
	node->node.cookie = node;
	cspf_node_add(&rb->ctx, &node->node);

	INIT_IV_AVL_TREE(&node->edges, compare_edges);

	rb->num_nodes++;
	iv_avl_tree_insert(&rb->nodes, &node->an);

	return node;
}

static struct edge *find_edge(struct node *from, uint8_t *to)
{
	struct iv_avl_node *an;

	an = from->edges.root;
	while (an != NULL) {
		struct edge *edge;
		int ret;

		edge = iv_container_of(an, struct edge, an);

		ret = memcmp(to, edge->to->id, NODE_ID_LEN);
		if (ret == 0)
			return edge;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int map_peer_type(enum peer_type forward, enum peer_type reverse)
{
	if (forward == PEER_TYPE_IPEER && reverse == PEER_TYPE_IPEER)
		return PEER_TYPE_IPEER;

	if ((forward == PEER_TYPE_CUSTOMER || forward == PEER_TYPE_IPEER) &&
	    (reverse == PEER_TYPE_TRANSIT || reverse == PEER_TYPE_IPEER))
		return PEER_TYPE_CUSTOMER;

	if ((forward == PEER_TYPE_TRANSIT || forward == PEER_TYPE_IPEER) &&
	    (reverse == PEER_TYPE_CUSTOMER || reverse == PEER_TYPE_IPEER))
		return PEER_TYPE_TRANSIT;

	return PEER_TYPE_EPEER;
}

static void register_edge(struct rt_builder *rb, struct node *from,
			  struct edge *edge, struct edge *back)
{
	enum peer_type type;

	type = map_peer_type(edge->to_type, back->to_type);

	cspf_edge_add(&rb->ctx, &edge->edge, &from->node, &edge->to->node,
		      type, edge->metric);
}

static void add_edge(struct rt_builder *rb, struct node *from,
		     uint8_t *_to, int metric, enum peer_type to_type)
{
	struct node *to;
	struct edge *edge;
	struct edge *edge2;

	to = get_node(rb, _to);

	edge = malloc(sizeof(*edge));
	if (edge == NULL)
		abort();

	edge->to = to;
	edge->metric = metric;
	edge->to_type = to_type;

	iv_avl_tree_insert(&from->edges, &edge->an);
	from->refcount++;

	edge2 = find_edge(to, from->id);
	if (edge2 != NULL) {
		register_edge(rb, from, edge, edge2);
		register_edge(rb, to, edge2, edge);
	}
}

static void unregister_edge(struct rt_builder *rb, struct node *from,
			    struct edge *edge, struct edge *back)
{
	enum peer_type type;

	type = map_peer_type(edge->to_type, back->to_type);

	cspf_edge_del(&rb->ctx, &edge->edge, &from->node,
		      &edge->to->node, type);
}

static void put_node(struct rt_builder *rb, struct node *node)
{
	if (!--node->refcount) {
		rb->num_nodes--;
		iv_avl_tree_delete(&rb->nodes, &node->an);
		cspf_node_del(&rb->ctx, &node->node);
		free(node);
	}
}

static void del_edge(struct rt_builder *rb, struct node *from, uint8_t *to)
{
	struct edge *edge;

	edge = find_edge(from, to);
	if (edge != NULL) {
		struct edge *edge2;

		edge2 = find_edge(edge->to, from->id);
		if (edge2 != NULL) {
			unregister_edge(rb, from, edge, edge2);
			unregister_edge(rb, edge->to, edge2, edge);
		}

		iv_avl_tree_delete(&from->edges, &edge->an);
		put_node(rb, from);
		put_node(rb, edge->to);

		free(edge);
	}
}

struct attr_cb_data {
	struct rt_builder	*rb;
	struct node		*node;
};

static void attr_add(void *_cb, struct lsa_attr *attr)
{
	struct attr_cb_data *cb = _cb;
	struct rt_builder *rb = cb->rb;
	struct node *node = cb->node;

	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN) {
		uint8_t *to;
		struct lsa_attr_set *set;
		struct lsa_attr *attr2;
		int metric;
		int peer_type;

		to = lsa_attr_key(attr);

		if (!attr->data_is_attr_set)
			return;
		set = lsa_attr_data(attr);

		attr2 = lsa_attr_set_find_attr(set, LSA_PEER_ATTR_TYPE_METRIC,
					       NULL, 0);
		if (attr2 == NULL || attr2->datalen != 2)
			return;
		metric = ntohs(*((uint16_t *)lsa_attr_data(attr2)));

		attr2 = lsa_attr_set_find_attr(set,
					       LSA_PEER_ATTR_TYPE_PEER_TYPE,
					       NULL, 0);
		if (attr2 == NULL || attr2->datalen != 1)
			return;
		peer_type = *((uint8_t *)lsa_attr_data(attr2));

		if (peer_type == LSA_PEER_TYPE_EPEER)
			add_edge(rb, node, to, metric, PEER_TYPE_EPEER);
		else if (peer_type == LSA_PEER_TYPE_CUSTOMER)
			add_edge(rb, node, to, metric, PEER_TYPE_CUSTOMER);
		else if (peer_type == LSA_PEER_TYPE_TRANSIT)
			add_edge(rb, node, to, metric, PEER_TYPE_TRANSIT);
		else if (peer_type == LSA_PEER_TYPE_IPEER)
			add_edge(rb, node, to, metric, PEER_TYPE_IPEER);
	}
}

static void attr_del(void *_cb, struct lsa_attr *attr)
{
	struct attr_cb_data *cb = _cb;
	struct rt_builder *rb = cb->rb;
	struct node *node = cb->node;

	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN)
		del_edge(rb, node, lsa_attr_key(attr));
}

static void lsa_add(void *_rb, struct lsa *a)
{
	struct rt_builder *rb = _rb;
	struct attr_cb_data cb;

	cb.rb = rb;
	cb.node = get_node(rb, a->id);

	lsa_diff(NULL, a, &cb, attr_add, NULL, attr_del);

	put_node(rb, cb.node);

	recompute_rtable(rb);
}

static void lsa_mod(void *_rb, struct lsa *a, struct lsa *b)
{
	struct rt_builder *rb = _rb;
	struct attr_cb_data cb;

	cb.rb = rb;
	cb.node = get_node(rb, a->id);

	lsa_diff(a, b, &cb, attr_add, NULL, attr_del);

	put_node(rb, cb.node);

	recompute_rtable(rb);
}

static void lsa_del(void *_rb, struct lsa *a)
{
	struct rt_builder *rb = _rb;
	struct attr_cb_data cb;

	cb.rb = rb;
	cb.node = get_node(rb, a->id);

	lsa_diff(a, NULL, &cb, attr_add, NULL, attr_del);

	put_node(rb, cb.node);

	recompute_rtable(rb);
}


struct rtable_entry {
	uint8_t			dest[16];
	uint8_t			nh[16];
};

struct rtable {
	int			num_entries;
	struct rtable_entry	entry[0];
};

static struct node *find_nexthop(struct node *node, struct node *us)
{
	struct node *a;
	struct node *b;
	struct node *c;

	a = node;

	b = cspf_node_parent(&a->node);
	if (b == NULL)
		return NULL;

	c = cspf_node_parent(&b->node);
	while (c != NULL) {
		a = b;
		b = c;
		c = cspf_node_parent(&c->node);
	}

	if (b != us)
		return NULL;

	return a;
}

static void rtable_add(struct rtable *rt, struct node *dest, struct node *nh)
{
	struct rtable_entry *ent;

	ent = &rt->entry[rt->num_entries++];
	v6_global_addr_from_key_id(ent->dest, dest->id);
	v6_global_addr_from_key_id(ent->nh, nh->id);
}

static int comp(const void *_a, const void *_b)
{
	const struct rtable_entry *a = _a;
	const struct rtable_entry *b = _b;

	return memcmp(a->dest, b->dest, 16);
}

static void rtable_sort(struct rtable *rt)
{
	qsort(rt->entry, rt->num_entries, sizeof(struct rtable_entry), comp);
}

static struct rtable *compute_rtable(struct rt_builder *rb)
{
	struct rtable *rt;
	struct node *from;

	rt = malloc(sizeof(*rt) + rb->num_nodes * sizeof(struct rtable_entry));
	if (rt == NULL)
		return NULL;

	rt->num_entries = 0;

	from = find_node(rb, rb->source);
	if (from != NULL) {
		struct iv_avl_node *an;

		cspf_run(&rb->ctx, &from->node);

		iv_avl_tree_for_each (an, &rb->nodes) {
			struct node *dest;
			struct node *nh;

			dest = iv_container_of(an, struct node, an);

			nh = find_nexthop(dest, from);
			if (nh != NULL && nh != dest)
				rtable_add(rt, dest, nh);
		}
	}

	rtable_sort(rt);

	return rt;
}

static void recompute_rtable(struct rt_builder *rb)
{
	struct rtable *rt = rb->rt;
	struct rtable *newrt;
	int ia;
	int numa;
	int ib;
	int numb;

	newrt = compute_rtable(rb);

	ia = 0;
	numa = (rt != NULL) ? rt->num_entries : 0;
	ib = 0;
	numb = (newrt != NULL) ? newrt->num_entries : 0;

	while (ia < numa && ib < numb) {
		struct rtable_entry *ea = rt->entry + ia;
		struct rtable_entry *eb = newrt->entry + ib;
		int ret;

		ret = memcmp(ea->dest, eb->dest, 16);

		if (ret < 0) {
			rb->rt_del(rb->cookie, ea->dest, ea->nh);
			ia++;
		} else if (ret > 0) {
			rb->rt_add(rb->cookie, eb->dest, eb->nh);
			ib++;
		} else {
			if (memcmp(ea->nh, eb->nh, 16)) {
				rb->rt_mod(rb->cookie, ea->dest,
					   ea->nh, eb->nh);
			}

			ia++;
			ib++;
		}
	}

	while (ia < numa) {
		struct rtable_entry *ea = rt->entry + ia;

		rb->rt_del(rb->cookie, ea->dest, ea->nh);
		ia++;
	}

	while (ib < numb) {
		struct rtable_entry *eb = newrt->entry + ib;

		rb->rt_add(rb->cookie, eb->dest, eb->nh);
		ib++;
	}

	free(rb->rt);
	rb->rt = newrt;
}


void rt_builder_init(struct rt_builder *rb)
{
	rb->rl.cookie = rb;
	rb->rl.lsa_add = lsa_add;
	rb->rl.lsa_mod = lsa_mod;
	rb->rl.lsa_del = lsa_del;

	spf_init(&rb->ctx);

	rb->num_nodes = 0;

	INIT_IV_AVL_TREE(&rb->nodes, compare_nodes);

	rb->rt = NULL;
}

void rt_builder_deinit(struct rt_builder *rb)
{
	if (rb->rt)
		free(rb->rt);
}
