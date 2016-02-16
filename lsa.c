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
#include "lsa_serialise.h"

static int lsa_attr_size(struct lsa_attr *attr);

static int lsa_attr_compare_keys(struct lsa_attr *a, struct lsa_attr *b)
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
	lsa->bytes = MAX_SERIALISED_INT_LEN + NODE_ID_LEN;
	memcpy(lsa->id, id, NODE_ID_LEN);
	INIT_IV_AVL_TREE(&lsa->root.attrs, compare_attr_keys);

	return lsa;
}

struct lsa *lsa_get(struct lsa *lsa)
{
	lsa->refcount++;

	return lsa;
}

static void attr_tree_free(struct lsa *lsa, struct iv_avl_node *root)
{
	struct lsa_attr *attr = iv_container_of(root, struct lsa_attr, an);

	lsa->bytes -= lsa_attr_size(attr);

	if (attr->an.left != NULL)
		attr_tree_free(lsa, attr->an.left);

	if (attr->an.right != NULL)
		attr_tree_free(lsa, attr->an.right);

	if (attr->data_is_attr_set) {
		struct lsa_attr_set *set;

		set = lsa_attr_data(attr);
		attr_tree_free(lsa, set->attrs.root);
	}

	free(attr);
}

void lsa_put(struct lsa *lsa)
{
	if (!--lsa->refcount) {
		if (!iv_avl_tree_empty(&lsa->root.attrs))
			attr_tree_free(lsa, lsa->root.attrs.root);
		free(lsa);
	}
}

static void lsa_attr_set_clone(struct lsa *lsa, struct lsa_attr_set *dst,
			       struct lsa_attr_set *src)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &src->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		if (attr->data_is_attr_set) {
			struct lsa_attr_set *s;
			struct lsa_attr_set *d;

			s = lsa_attr_data(attr);
			d = lsa_attr_set_add_attr_set(lsa, dst, attr->type,
					lsa_attr_key(attr), attr->keylen);

			lsa_attr_set_clone(lsa, d, s);
		} else {
			lsa_attr_set_add_attr(lsa, dst, attr->type,
					lsa_attr_key(attr), attr->keylen,
					lsa_attr_data(attr), attr->datalen);
		}
	}
}

struct lsa *lsa_clone(struct lsa *lsa)
{
	struct lsa *newlsa;

	newlsa = lsa_alloc(lsa->id);
	if (newlsa == NULL)
		return NULL;

	lsa_attr_set_clone(newlsa, &newlsa->root, &lsa->root);

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

struct lsa_attr *lsa_find_attr(struct lsa *lsa, int type,
			       void *key, int keylen)
{
	return lsa_attr_set_find_attr(&lsa->root, type, key, keylen);
}

struct lsa_attr *lsa_attr_set_find_attr(struct lsa_attr_set *set,
					int type, void *key, int keylen)
{
	struct {
		struct lsa_attr		skey;
		uint8_t			kkey[0];
	} *s;
	struct iv_avl_node *an;

	s = alloca(sizeof(*s) + keylen);

	s->skey.type = type;
	s->skey.keylen = keylen;
	memcpy(lsa_attr_key(&s->skey), key, keylen);

	an = set->attrs.root;
	while (an != NULL) {
		struct lsa_attr *attr;
		int ret;

		attr = iv_container_of(an, struct lsa_attr, an);

		ret = lsa_attr_compare_keys(&s->skey, attr);
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

	size = 2 * MAX_SERIALISED_INT_LEN;

	if (attr->keylen)
		size += MAX_SERIALISED_INT_LEN + attr->keylen;

	size += MAX_SERIALISED_INT_LEN;
	if (!attr->data_is_attr_set)
		size += attr->datalen;

	return size;
}

void lsa_add_attr(struct lsa *lsa, int type, void *key, int keylen,
		  void *data, int datalen)
{
	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_add_attr: called on an LSA with "
				"refcount %d\n", lsa->refcount);
		abort();
	}

	lsa_attr_set_add_attr(lsa, &lsa->root, type, key, keylen,
			      data, datalen);
}

static struct lsa_attr *attr_alloc(int type, int keylen, int datalen)
{
	struct lsa_attr *attr;

	attr = malloc(sizeof(*attr) + ROUND_UP(keylen) + datalen);
	if (attr == NULL)
		abort();

	attr->type = type;
	attr->data_is_attr_set = 0;
	attr->keylen = keylen;
	attr->datalen = datalen;

	return attr;
}

void lsa_attr_set_add_attr(struct lsa *lsa, struct lsa_attr_set *set, int type,
			   void *key, int keylen, void *data, int datalen)
{
	struct lsa_attr *attr;

	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_attr_set_add_attr: called on an LSA "
				"with refcount %d\n", lsa->refcount);
		abort();
	}

	attr = lsa_attr_set_find_attr(set, type, key, keylen);
	if (attr != NULL)
		abort();

	attr = attr_alloc(type, keylen, datalen);

	if (keylen)
		memcpy(lsa_attr_key(attr), key, keylen);
	if (datalen)
		memcpy(lsa_attr_data(attr), data, datalen);

	lsa->bytes += lsa_attr_size(attr);
	iv_avl_tree_insert(&set->attrs, &attr->an);
}

struct lsa_attr_set *lsa_add_attr_set(struct lsa *lsa, int type,
				      void *key, int keylen)
{
	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_add_attr_set: called on an LSA "
				"with refcount %d\n", lsa->refcount);
		abort();
	}

	return lsa_attr_set_add_attr_set(lsa, &lsa->root, type, key, keylen);
}

struct lsa_attr_set *
lsa_attr_set_add_attr_set(struct lsa *lsa, struct lsa_attr_set *set,
			  int type, void *key, int keylen)
{
	struct lsa_attr *attr;
	struct lsa_attr_set *child;

	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_attr_set_add_attr_set: called on an "
				"LSA with refcount %d\n", lsa->refcount);
		abort();
	}

	attr = lsa_attr_set_find_attr(set, type, key, keylen);
	if (attr != NULL)
		abort();

	attr = attr_alloc(type, keylen, sizeof(struct lsa_attr_set));
	attr->data_is_attr_set = 1;
	if (keylen)
		memcpy(lsa_attr_key(attr), key, keylen);

	lsa->bytes += lsa_attr_size(attr);
	iv_avl_tree_insert(&set->attrs, &attr->an);

	child = lsa_attr_data(attr);
	INIT_IV_AVL_TREE(&child->attrs, compare_attr_keys);

	return child;
}

void lsa_del_attr(struct lsa *lsa, struct lsa_attr *attr)
{
	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_del_attr: called on an LSA with "
				"refcount %d\n", lsa->refcount);
		abort();
	}

	lsa->bytes -= lsa_attr_size(attr);
	iv_avl_tree_delete(&lsa->root.attrs, &attr->an);

	if (attr->data_is_attr_set) {
		struct lsa_attr_set *set;

		set = lsa_attr_data(attr);
		if (!iv_avl_tree_empty(&set->attrs))
			attr_tree_free(lsa, set->attrs.root);
	}

	free(attr);
}

void lsa_del_attr_bykey(struct lsa *lsa, int type, void *key, int keylen)
{
	struct lsa_attr *attr;

	if (lsa->refcount != 1) {
		fprintf(stderr, "lsa_del_attr_bykey: called on an LSA with "
				"refcount %d\n", lsa->refcount);
		abort();
	}

	attr = lsa_find_attr(lsa, type, key, keylen);
	if (attr == NULL)
		abort();

	lsa_del_attr(lsa, attr);
}
