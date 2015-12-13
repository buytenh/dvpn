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
#include <limits.h>
#include "spf.h"

void spf_init(struct spf_context *ctx)
{
	INIT_IV_LIST_HEAD(&ctx->nodes);
	ctx->num_nodes = 0;
}

void spf_node_add(struct spf_context *ctx, struct spf_node *node)
{
	iv_list_add_tail(&node->list, &ctx->nodes);
	INIT_IV_LIST_HEAD(&node->edges);

	ctx->num_nodes++;
}

void spf_edge_add(struct spf_node *from, struct spf_edge *edge)
{
	iv_list_add_tail(&edge->list, &from->edges);
}

static void push_down(struct spf_node **heap, int heapsize)
{
	int index;

	index = 0;
	while (1) {
		int min;
		int child;
		struct spf_node *temp;

		min = index;

		child = 2 * index + 1;
		if (child < heapsize && heap[min]->cost > heap[child]->cost)
			min = child;

		child = 2 * index + 2;
		if (child < heapsize && heap[min]->cost > heap[child]->cost)
			min = child;

		if (index == min)
			break;

		temp = heap[index];
		heap[index] = heap[min];
		heap[min] = temp;

		heap[index]->heapidx = index;
		heap[min]->heapidx = min;

		index = min;
	}
}

static void pull_up(struct spf_node **heap, int index)
{
	while (index) {
		int parent;
		struct spf_node *temp;

		parent = (index - 1) / 2;
		if (heap[parent]->cost > heap[index]->cost)
			break;

		temp = heap[index];
		heap[index] = heap[parent];
		heap[parent] = temp;

		heap[index]->heapidx = index;
		heap[parent]->heapidx = parent;

		index = parent;
	}
}

void spf_run(struct spf_context *ctx, struct spf_node *source)
{
	struct iv_list_head *lh;
	struct spf_node *heap[ctx->num_nodes];
	int heapsize;

	iv_list_for_each (lh, &ctx->nodes) {
		struct spf_node *node;

		node = iv_container_of(lh, struct spf_node, list);
		node->parent = NULL;
		node->cost = INT_MAX;
		node->heapidx = -1;
	}

	source->cost = 0;
	source->heapidx = 0;

	heap[0] = source;
	heapsize = 1;

	while (heapsize) {
		struct spf_node *from;

		from = heap[0];

		from->heapidx = -1;
		if (--heapsize) {
			heap[0] = heap[heapsize];
			push_down(heap, heapsize);
		}

		iv_list_for_each (lh, &from->edges) {
			struct spf_edge *edge;
			struct spf_node *to;
			int cost;

			edge = iv_container_of(lh, struct spf_edge, list);

			to = edge->to;
			cost = from->cost + edge->cost;

			if (cost >= to->cost)
				continue;

			if (to->cost == INT_MAX) {
				to->heapidx = heapsize;
				heap[heapsize] = to;
				heapsize++;
			}

			to->parent = from;
			to->cost = cost;
			pull_up(heap, to->heapidx);
		}
	}
}
