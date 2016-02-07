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

#include <stdio.h>
#include <stdlib.h>
#include <iv_list.h>
#include <string.h>
#include "lsa.h"

static int compare_attr_keys(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct lsa_attr *a = iv_container_of(_a, struct lsa_attr, an);
	struct lsa_attr *b = iv_container_of(_b, struct lsa_attr, an);

	return lsa_attr_compare_keys(a, b);
}

struct lsa *lsa_alloc(uint8_t *id)
{
	struct lsa *lsa;

	lsa = malloc(sizeof(*lsa));
	if (lsa == NULL)
		return NULL;

	lsa->refcount = 1;
	lsa->size = NODE_ID_LEN;
	memcpy(lsa->id, id, NODE_ID_LEN);
	INIT_IV_AVL_TREE(&lsa->attrs, compare_attr_keys);

	return lsa;
}

struct lsa *lsa_get(struct lsa *lsa)
{
	lsa->refcount++;

	return lsa;
}

static void attr_tree_free(struct iv_avl_node *root)
{
	if (root->left != NULL)
		attr_tree_free(root->left);

	if (root->right != NULL)
		attr_tree_free(root->right);

	free(iv_container_of(root, struct lsa_attr, an));
}

void lsa_put(struct lsa *lsa)
{
	if (!--lsa->refcount) {
		if (lsa->attrs.root != NULL)
			attr_tree_free(lsa->attrs.root);
		free(lsa);
	}
}

struct lsa *lsa_clone(struct lsa *lsa)
{
	struct lsa *newlsa;
	struct iv_avl_node *an;

	newlsa = lsa_alloc(lsa->id);
	if (newlsa == NULL)
		return NULL;

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		lsa_attr_add(newlsa, attr->type,
			     lsa_attr_key(attr), attr->keylen,
			     lsa_attr_data(attr), attr->datalen);
	}

	return newlsa;
}


#define ROUND_UP(size)	(((size) + 7) & ~7)

void *lsa_attr_key(struct lsa_attr *attr)
{
	if (attr->keylen)
		return attr->buf;

	return NULL;
}

void *lsa_attr_data(struct lsa_attr *attr)
{
	if (attr->datalen)
		return attr->buf + ROUND_UP(attr->keylen);

	return NULL;
}

int lsa_attr_compare_keys(struct lsa_attr *a, struct lsa_attr *b)
{
	int len;
	int ret;

	if (a->type < b->type)
		return -1;
	if (a->type > b->type)
		return 1;

	len = a->keylen;
	if (len > b->keylen)
		len = b->keylen;

	ret = memcmp(lsa_attr_key(a), lsa_attr_key(b), len);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	if (a->keylen < b->keylen)
		return -1;
	if (a->keylen > b->keylen)
		return 1;

	return 0;
}

struct lsa_attr *lsa_attr_find(struct lsa *lsa, int type,
			       void *key, int keylen)
{
	struct {
		struct lsa_attr		skey;
		uint8_t			kkey[keylen];
	} s;
	struct iv_avl_node *an;

	s.skey.type = type;
	s.skey.keylen = keylen;
	memcpy(lsa_attr_key(&s.skey), key, keylen);

	an = lsa->attrs.root;
	while (an != NULL) {
		struct lsa_attr *attr;
		int ret;

		attr = iv_container_of(an, struct lsa_attr, an);

		ret = lsa_attr_compare_keys(&s.skey, attr);
		if (ret == 0)
			return attr;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int lsa_attr_size(struct lsa_attr *attr)
{
	int size;

	size = 1;
	if (attr->keylen)
		size += 2 + attr->keylen;
	size += 2 + attr->datalen;

	return size;
}

void lsa_attr_add(struct lsa *lsa, int type, void *key, int keylen,
		  void *data, int datalen)
{
	struct lsa_attr *attr;

	attr = lsa_attr_find(lsa, type, key, keylen);
	if (attr != NULL)
		abort();

	attr = malloc(sizeof(*attr) + ROUND_UP(keylen) + datalen);
	if (attr == NULL)
		abort();

	attr->type = type;
	attr->keylen = keylen;
	if (keylen)
		memcpy(lsa_attr_key(attr), key, keylen);
	attr->datalen = datalen;
	if (datalen)
		memcpy(lsa_attr_data(attr), data, datalen);

	lsa->size += lsa_attr_size(attr);
	iv_avl_tree_insert(&lsa->attrs, &attr->an);
}

void lsa_attr_del(struct lsa *lsa, struct lsa_attr *attr)
{
	lsa->size -= lsa_attr_size(attr);
	iv_avl_tree_delete(&lsa->attrs, &attr->an);

	free(attr);
}

void lsa_attr_del_key(struct lsa *lsa, int type, void *key, int keylen)
{
	struct lsa_attr *attr;

	attr = lsa_attr_find(lsa, type, key, keylen);
	if (attr == NULL)
		abort();

	lsa_attr_del(lsa, attr);
}
