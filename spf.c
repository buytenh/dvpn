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
#include <iv_list.h>
#include "spf.h"

void spf_init(struct spf_context *ctx)
{
	INIT_IV_LIST_HEAD(&ctx->nodes);
	INIT_IV_LIST_HEAD(&ctx->edges);
}

void spf_node_add(struct spf_context *ctx, struct spf_node *node)
{
	iv_list_add_tail(&node->list, &ctx->nodes);
}

void spf_edge_add(struct spf_context *ctx, struct spf_edge *edge)
{
	iv_list_add_tail(&edge->list, &ctx->edges);
}

void spf_run(struct spf_context *ctx, struct spf_node *source)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &ctx->nodes) {
		struct spf_node *node;

		node = iv_container_of(lh, struct spf_node, list);
		node->parent = NULL;
		node->cost = (node == source) ? 0 : -1;
	}

	while (1) {
		struct spf_edge *bestedge;
		int bestcost;

		bestedge = NULL;
		bestcost = -1;

		iv_list_for_each (lh, &ctx->edges) {
			struct spf_edge *edge;
			int cost;

			edge = iv_container_of(lh, struct spf_edge, list);

			if (edge->from->cost == -1 || edge->to->cost != -1)
				continue;

			cost = edge->from->cost + edge->cost;
			if (bestedge == NULL || cost < bestcost) {
				bestedge = edge;
				bestcost = cost;
			}
		}

		if (bestedge == NULL)
			break;

		bestedge->to->parent = bestedge->from;
		bestedge->to->cost = bestcost;
	}
}
