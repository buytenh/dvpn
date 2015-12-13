/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015 Lennert Buytenhek
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
#include "cspf.h"

void cspf_node_add(struct spf_context *ctx, struct cspf_node *node)
{
	node->a.cookie = node->cookie;
	spf_node_add(ctx, &node->a);

	node->b.cookie = node->cookie;
	spf_node_add(ctx, &node->b);

	node->ab.to = &node->b;
	node->ab.cost = 0;
	spf_edge_add(&node->a, &node->ab);
}

void cspf_edge_add(struct spf_context *ctx, struct cspf_edge *edge,
		   struct cspf_node *from, struct cspf_node *to,
		   enum peer_type to_type, int cost)
{
	switch (to_type) {
	case PEER_TYPE_EPEER:
		edge->e0.to = &to->b;
		edge->e0.cost = cost;
		spf_edge_add(&from->a, &edge->e0);
		break;

	case PEER_TYPE_CUSTOMER:
		edge->e0.to = &to->b;
		edge->e0.cost = cost;
		spf_edge_add(&from->b, &edge->e0);
		break;

	case PEER_TYPE_TRANSIT:
		edge->e0.to = &to->a;
		edge->e0.cost = cost;
		spf_edge_add(&from->a, &edge->e0);
		break;

	case PEER_TYPE_IPEER:
		edge->e0.to = &to->a;
		edge->e0.cost = cost;
		spf_edge_add(&from->a, &edge->e0);
		edge->e1.to = &to->b;
		edge->e1.cost = cost;
		spf_edge_add(&from->b, &edge->e1);
		break;

	default:
		fprintf(stderr, "cspf_edge_add: invalid peer type %d\n",
			to_type);
		break;
	}
}

void cspf_run(struct spf_context *ctx, struct cspf_node *source)
{
	spf_run(ctx, &source->a);
}

void *cspf_node_parent(struct cspf_node *node)
{
	struct spf_node *parent;

	parent = node->b.parent;
	if (parent == &node->a)
		parent = node->a.parent;

	if (parent != NULL)
		return parent->cookie;

	return NULL;
}

int cspf_node_cost(struct cspf_node *node)
{
	return node->b.cost;
}
