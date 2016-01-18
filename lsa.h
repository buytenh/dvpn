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

#ifndef __LSA_H
#define __LSA_H

#include <iv_avl.h>

struct lsa {
	int			refcount;
	uint8_t			id[32];
	struct iv_avl_tree	attrs;
};

struct lsa_attr {
	struct iv_avl_node	an;
	int			type;
	int			keylen;
	void			*key;
	int			datalen;
	void			*data;
};

struct lsa *lsa_alloc(uint8_t *id);
void lsa_put(struct lsa *lsa);
int lsa_attr_compare_keys(struct lsa_attr *a, struct lsa_attr *b);
struct lsa_attr *lsa_attr_find(struct lsa *lsa, int type,
			       void *key, int keylen);
void lsa_attr_add(struct lsa *lsa, int type, void *key, int keylen,
		  void *data, int datalen);
void lsa_attr_del(struct lsa *lsa, struct lsa_attr *attr);
void lsa_attr_del_key(struct lsa *lsa, int type, void *key, int keylen);


#endif
