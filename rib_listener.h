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

#ifndef __RIB_LISTENER_H
#define __RIB_LISTENER_H

#include <iv_list.h>
#include "lsa.h"

#define RIB_COST_UNREACHABLE	0xfffffffe
#define RIB_COST_INELIGIBLE	0xffffffff

struct rib_listener {
	void	*cookie;
	void	(*lsa_add)(void *cookie, struct lsa *lsa, uint32_t cost);
	void	(*lsa_mod)(void *cookie, struct lsa *oldlsa, uint32_t oldcost,
			   struct lsa *newlsa, uint32_t newcost);
	void	(*lsa_del)(void *cookie, struct lsa *lsa, uint32_t cost);

	struct iv_list_head	list;
};


#endif
