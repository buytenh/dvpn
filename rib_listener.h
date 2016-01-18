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

#include "lsa.h"

struct rib_listener {
	void			*cookie;
	void			(*lsa_add)(void *, struct lsa *);
	void			(*lsa_mod)(void *, struct lsa *, struct lsa *);
	void			(*lsa_del)(void *, struct lsa *);

	struct iv_list_head	list;
};

struct rib_listener *debug_listener_new(char *name);
void debug_listener_free(struct rib_listener *rl);


#endif
