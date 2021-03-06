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

#ifndef __LSA_DIFF_H
#define __LSA_DIFF_H

#include "lsa.h"

int lsa_diff(struct lsa *a, struct lsa *b, void *cookie,
	     void (*attr_add)(void *, struct lsa_attr *),
	     void (*attr_mod)(void *, struct lsa_attr *, struct lsa_attr *),
	     void (*attr_del)(void *, struct lsa_attr *));


#endif
