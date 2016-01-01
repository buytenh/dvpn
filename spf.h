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

#ifndef __SPF_H
#define __SPF_H

#include <iv_list.h>

#define SPF_ID_LEN	20

struct spf_context
{
	struct iv_list_head	nodes;
	int			num_nodes;
};

struct spf_node
{
	uint8_t			*id;
	void			*cookie;

	struct iv_list_head	list;
	struct iv_list_head	edges;
	struct spf_node		*parent;
	int			cost;
	int			heapidx;
};

struct spf_edge
{
	struct spf_node		*to;
	int			cost;

	struct iv_list_head	list;
};

void spf_init(struct spf_context *ctx);
void spf_node_add(struct spf_context *ctx, struct spf_node *node);
void spf_edge_add(struct spf_node *from, struct spf_edge *edge);
void spf_run(struct spf_context *ctx, struct spf_node *source);


#endif
