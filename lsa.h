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

#define NODE_ID_LEN	32

struct lsa_attr_set {
	struct iv_avl_tree	attrs;
};

struct lsa {
	int			refcount;
	size_t			bytes;
	uint8_t			id[NODE_ID_LEN];
	struct lsa_attr_set	root;
};

struct lsa *lsa_alloc(uint8_t *id);
struct lsa *lsa_get(struct lsa *lsa);
void lsa_put(struct lsa *lsa);
struct lsa *lsa_clone(struct lsa *lsa);


struct lsa_attr {
	struct iv_avl_node	an;
	int			type;
	unsigned		data_is_attr_set:1;
	unsigned		attr_signed:1;
	size_t			keylen;
	size_t			datalen;
	uint8_t			buf[0];
};

void *lsa_attr_key(struct lsa_attr *attr);
void *lsa_attr_data(struct lsa_attr *attr);

struct lsa_attr *lsa_find_attr(struct lsa *lsa, int type,
			       void *key, size_t keylen);
struct lsa_attr *lsa_attr_set_find_attr(struct lsa_attr_set *set,
					int type, void *key, size_t keylen);

int lsa_add_attr(struct lsa *lsa, int type, void *key, size_t keylen,
		 void *data, size_t datalen);
int lsa_attr_set_add_attr(struct lsa *lsa, struct lsa_attr_set *set, int type,
			  void *key, size_t keylen, void *data, size_t datalen);

struct lsa_attr_set *lsa_add_attr_set(struct lsa *lsa, int type,
				      void *key, size_t keylen);
struct lsa_attr_set *lsa_attr_set_add_attr_set(struct lsa *lsa,
					       struct lsa_attr_set *set,
					       int type, void *key,
					       size_t keylen);

void lsa_del_attr(struct lsa *lsa, struct lsa_attr *attr);

void lsa_del_attr_bykey(struct lsa *lsa, int type, void *key, size_t keylen);


#endif
