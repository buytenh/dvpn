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

#include "rib_listener.h"

struct rt_builder {
	struct loc_rib	*rib;
	uint8_t		*myid;
	void		*cookie;
	void		(*rt_add)(void *cookie, uint8_t *dest, uint8_t *nh);
	void		(*rt_mod)(void *cookie, uint8_t *dest, uint8_t *oldnh,
				  uint8_t *newnh);
	void		(*rt_del)(void *cookie, uint8_t *dest, uint8_t *nh);

	struct rib_listener	rl;
};

void rt_builder_init(struct rt_builder *rb);
void rt_builder_deinit(struct rt_builder *rb);


#endif
