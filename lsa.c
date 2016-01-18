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
	memcpy(lsa->id, id, 32);
	INIT_IV_AVL_TREE(&lsa->attrs, compare_attr_keys);

	return lsa;
}

static void lsa_attr_free(struct lsa_attr *attr)
{
	if (attr->key != NULL)
		free(attr->key);

	if (attr->data != NULL)
		free(attr->data);

	free(attr);
}

static void attr_tree_free(struct iv_avl_node *root)
{
	if (root->left != NULL)
		attr_tree_free(root->left);

	if (root->right != NULL)
		attr_tree_free(root->right);

	lsa_attr_free(iv_container_of(root, struct lsa_attr, an));
}

void lsa_put(struct lsa *lsa)
{
	if (!--lsa->refcount) {
		attr_tree_free(lsa->attrs.root);
		free(lsa);
	}
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

	ret = memcmp(a->key, b->key, len);
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
	struct lsa_attr skey;
	struct iv_avl_node *an;

	skey.type = type;
	skey.key = key;
	skey.keylen = keylen;

	an = lsa->attrs.root;
	while (an != NULL) {
		struct lsa_attr *attr;
		int ret;

		attr = iv_container_of(an, struct lsa_attr, an);

		ret = lsa_attr_compare_keys(&skey, attr);
		if (ret == 0)
			return attr;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

void lsa_attr_add(struct lsa *lsa, int type, void *key, int keylen,
		  void *data, int datalen)
{
	struct lsa_attr *attr;

	attr = lsa_attr_find(lsa, type, key, keylen);
	if (attr != NULL)
		abort();

	attr = malloc(sizeof(*attr));
	if (attr == NULL)
		abort();

	attr->type = type;

	if (keylen) {
		attr->keylen = keylen;
		attr->key = malloc(keylen);
		if (attr->key == NULL)
			abort();
		memcpy(attr->key, key, keylen);
	} else {
		attr->keylen = 0;
		attr->key = NULL;
	}

	if (datalen) {
		attr->datalen = datalen;
		attr->data = malloc(datalen);
		if (attr->data == NULL)
			abort();
		memcpy(attr->data, data, datalen);
	} else {
		attr->datalen = 0;
		attr->data = NULL;
	}

	iv_avl_tree_insert(&lsa->attrs, &attr->an);
}

void lsa_attr_del(struct lsa *lsa, struct lsa_attr *attr)
{
	iv_avl_tree_delete(&lsa->attrs, &attr->an);
	lsa_attr_free(attr);
}

void lsa_attr_del_key(struct lsa *lsa, int type, void *key, int keylen)
{
	struct lsa_attr *attr;

	attr = lsa_attr_find(lsa, type, key, keylen);
	if (attr == NULL)
		abort();

	lsa_attr_del(lsa, attr);
}
