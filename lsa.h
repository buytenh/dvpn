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
#include "util.h"

struct lsa_attr_set {
	struct iv_avl_tree	attrs;
};

struct lsa {
	int			refcount;
	int			bytes;
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
	int			keylen;
	int			datalen;
	uint8_t			buf[0];
};

void *lsa_attr_key(struct lsa_attr *attr);
void *lsa_attr_data(struct lsa_attr *attr);

struct lsa_attr *lsa_find_attr(struct lsa *lsa, int type,
			       void *key, int keylen);
struct lsa_attr *lsa_attr_set_find_attr(struct lsa_attr_set *set,
					int type, void *key, int keylen);

void lsa_add_attr(struct lsa *lsa, int type, void *key, int keylen,
		  void *data, int datalen);
void lsa_attr_set_add_attr(struct lsa *lsa, struct lsa_attr_set *set, int type,
			   void *key, int keylen, void *data, int datalen);

struct lsa_attr_set *lsa_add_attr_set(struct lsa *lsa, int type,
				      void *key, int keylen);
struct lsa_attr_set *lsa_attr_set_add_attr_set(struct lsa *lsa,
					       struct lsa_attr_set *set,
					       int type, void *key, int keylen);

void lsa_del_attr(struct lsa *lsa, struct lsa_attr *attr);

void lsa_del_attr_bykey(struct lsa *lsa, int type, void *key, int keylen);


#endif
