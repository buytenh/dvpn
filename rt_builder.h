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

#ifndef __RT_BUILDER_H
#define __RT_BUILDER_H

#include <iv_avl.h>
#include "rib_listener.h"
#include "spf.h"

struct rt_builder {
	struct loc_rib	*rib;
	uint8_t		*source;
	void		*cookie;
	void		(*rt_add)(void *, uint8_t *, uint8_t *);
	void		(*rt_mod)(void *, uint8_t *, uint8_t *, uint8_t *);
	void		(*rt_del)(void *, uint8_t *, uint8_t *);

	struct rib_listener	rl;
	struct spf_context	ctx;
	int			num_nodes;
	struct iv_avl_tree	nodes;
	struct rtable		*rt;
};

void rt_builder_init(struct rt_builder *rb);
void rt_builder_deinit(struct rt_builder *rb);


#endif
