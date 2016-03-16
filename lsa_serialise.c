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
#include "lsa_serialise.h"
#include "lsa_type.h"

struct dst {
	uint8_t		*dst;
	size_t		dstlen;
	size_t		off;
};

static void dst_append(struct dst *dst, const uint8_t *buf, size_t buflen)
{
	size_t off;

	off = dst->off;

	if (buflen > SIZE_MAX - off) {
		fprintf(stderr, "dst_append: buffer SIZE_MAX overflow\n");
		abort();
	}
	dst->off += buflen;

	if (off < dst->dstlen) {
		size_t space;

		space = dst->dstlen - off;
		if (space > buflen)
			space = buflen;

		memcpy(dst->dst + off, buf, space);
	}
}

static void dst_append_int(struct dst *dst, uint64_t value)
{
	uint8_t val[10];
	int i;

	val[0] = 0x80 | ((value >> 63) & 0x1);
	val[1] = 0x80 | ((value >> 56) & 0x7f);
	val[2] = 0x80 | ((value >> 49) & 0x7f);
	val[3] = 0x80 | ((value >> 42) & 0x7f);
	val[4] = 0x80 | ((value >> 35) & 0x7f);
	val[5] = 0x80 | ((value >> 28) & 0x7f);
	val[6] = 0x80 | ((value >> 21) & 0x7f);
	val[7] = 0x80 | ((value >> 14) & 0x7f);
	val[8] = 0x80 | ((value >> 7) & 0x7f);
	val[9] = value & 0x7f;

	i = 0;
	while (val[i] == 0x80)
		i++;

	dst_append(dst, val + i, sizeof(val) - i);
}

static size_t
lsa_attr_set_serialise_length(struct lsa_attr_set *set,
			      int signed_only, const uint8_t *preid);

static void __lsa_attr_serialise(struct dst *dst, struct lsa_attr *attr,
				 int signed_only, const uint8_t *preid)
{
	int flags;

	if (signed_only && !attr->attr_signed)
		return;

	dst_append_int(dst, attr->type);

	flags = 0;
	if (attr->keylen)
		flags |= LSA_ATTR_FLAG_HAS_KEY;
	if (attr->data_is_attr_set)
		flags |= LSA_ATTR_FLAG_DATA_IS_TLV;
	if (attr->attr_signed)
		flags |= LSA_ATTR_FLAG_SIGNED;

	dst_append_int(dst, flags);

	if (attr->keylen) {
		dst_append_int(dst, attr->keylen);
		dst_append(dst, lsa_attr_key(attr), attr->keylen);
	}

	if (attr->data_is_attr_set) {
		struct lsa_attr_set *set;
		size_t len;
		struct iv_avl_node *an;

		set = lsa_attr_data(attr);

		len = lsa_attr_set_serialise_length(set, signed_only, NULL);
		dst_append_int(dst, len);

		iv_avl_tree_for_each (an, &set->attrs) {
			struct lsa_attr *attr2;

			attr2 = iv_container_of(an, struct lsa_attr, an);
			__lsa_attr_serialise(dst, attr2, signed_only, NULL);
		}
	} else if (preid != NULL) {
		dst_append_int(dst, attr->datalen + NODE_ID_LEN);
		dst_append(dst, preid, NODE_ID_LEN);
		dst_append(dst, lsa_attr_data(attr), attr->datalen);
	} else {
		dst_append_int(dst, attr->datalen);
		dst_append(dst, lsa_attr_data(attr), attr->datalen);
	}
}

static void lsa_attrs_serialise(struct dst *dst, struct iv_avl_tree *attrs,
				int signed_only, const uint8_t *preid)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		if (attr->type == LSA_ATTR_TYPE_ADV_PATH)
			__lsa_attr_serialise(dst, attr, signed_only, preid);
		else
			__lsa_attr_serialise(dst, attr, signed_only, NULL);
	}
}

static size_t
lsa_attr_set_serialise_length(struct lsa_attr_set *set,
			      int signed_only, const uint8_t *preid)
{
	struct dst dst;

	dst.dst = NULL;
	dst.dstlen = 0;
	dst.off = 0;

	lsa_attrs_serialise(&dst, &set->attrs, signed_only, preid);

	return dst.off;
}

size_t lsa_serialise_length(struct lsa *lsa, int signed_only,
			    const uint8_t *preid)
{
	return NODE_ID_LEN +
		lsa_attr_set_serialise_length(&lsa->root, signed_only, preid);
}

size_t lsa_serialise(uint8_t *buf, size_t buflen, size_t serlen,
		     struct lsa *lsa, int signed_only, const uint8_t *preid)
{
	struct dst dst;

	dst.dst = buf;
	dst.dstlen = buflen;
	dst.off = 0;

	dst_append_int(&dst, serlen);
	serlen += dst.off;

	dst_append(&dst, lsa->id, NODE_ID_LEN);

	lsa_attrs_serialise(&dst, &lsa->root.attrs, signed_only, preid);

	if (serlen != dst.off) {
		fprintf(stderr, "lsa_serialise: lsa size %lu versus "
				"buffer size %lu\n", (unsigned long)serlen,
			(unsigned long)dst.off);
		abort();
	}

	return dst.off;
}

size_t lsa_attr_serialise_length(struct lsa_attr *attr)
{
	return lsa_attr_serialise(NULL, 0, attr);
}

size_t lsa_attr_serialise(uint8_t *buf, size_t buflen, struct lsa_attr *attr)
{
	struct dst dst;

	dst.dst = buf;
	dst.dstlen = buflen;
	dst.off = 0;

	__lsa_attr_serialise(&dst, attr, 0, NULL);

	return dst.off;
}
