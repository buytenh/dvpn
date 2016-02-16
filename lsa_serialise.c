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
	int		dstlen;
	int		off;
};

static void dst_append(struct dst *dst, uint8_t *buf, int buflen)
{
	int space;

	space = dst->dstlen - dst->off;
	if (space > buflen)
		space = buflen;

	if (space > 0)
		memcpy(dst->dst + dst->off, buf, space);

	dst->off += buflen;
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

static void
lsa_attr_serialise(struct dst *dst, struct lsa_attr *attr, uint8_t *preid)
{
	int flags;

	dst_append_int(dst, attr->type);

	flags = 0;
	if (attr->keylen)
		flags |= LSA_ATTR_FLAG_HAS_KEY;

	dst_append_int(dst, flags);

	if (attr->keylen) {
		dst_append_int(dst, attr->keylen);
		dst_append(dst, lsa_attr_key(attr), attr->keylen);
	}

	if (preid != NULL) {
		dst_append_int(dst, attr->datalen + NODE_ID_LEN);
		dst_append(dst, preid, NODE_ID_LEN);
	} else {
		dst_append_int(dst, attr->datalen);
	}
	dst_append(dst, lsa_attr_data(attr), attr->datalen);
}

static void
lsa_attrs_serialise(struct dst *dst, struct iv_avl_tree *attrs, uint8_t *preid)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		if (attr->type == LSA_ATTR_TYPE_ADV_PATH)
			lsa_attr_serialise(dst, attr, preid);
		else
			lsa_attr_serialise(dst, attr, NULL);
	}
}

int lsa_serialise_length(struct lsa *lsa, uint8_t *preid)
{
	struct dst dst;

	dst.dst = NULL;
	dst.dstlen = 0;
	dst.off = 0;

	dst_append(&dst, lsa->id, NODE_ID_LEN);

	lsa_attrs_serialise(&dst, &lsa->attrs, preid);

	return dst.off;
}

int lsa_serialise(uint8_t *buf, int buflen, int serlen,
		  struct lsa *lsa, uint8_t *preid)
{
	struct dst dst;

	dst.dst = buf;
	dst.dstlen = buflen;
	dst.off = 0;

	dst_append_int(&dst, serlen);
	serlen += dst.off;

	dst_append(&dst, lsa->id, NODE_ID_LEN);

	lsa_attrs_serialise(&dst, &lsa->attrs, preid);

	if (serlen != dst.off) {
		fprintf(stderr, "lsa_serialise: lsa size %d versus "
				"buffer size %d\n", serlen, dst.off);
		abort();
	}

	return dst.off;
}

int lsa_serialised_int_len(uint64_t value)
{
	int i;

	for (i = 1; i <= 10; i++) {
		value >>= 7;
		if (!value)
			return i;
	}

	abort();
}
