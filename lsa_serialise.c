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

static void dst_append_u16(struct dst *dst, int value)
{
	uint8_t val[2];

	val[0] = (value >> 8) & 0xff;
	val[1] = value & 0xff;
	dst_append(dst, val, 2);
}

int lsa_serialise(uint8_t *buf, int buflen, struct lsa *lsa, uint8_t *preid)
{
	struct dst dst;
	int size;
	struct iv_avl_node *an;

	dst.dst = buf;
	dst.dstlen = buflen;
	dst.off = 0;

	size = lsa->size;
	if (preid != NULL && !iv_avl_tree_empty(&lsa->attrs))
		size += NODE_ID_LEN;

	dst_append_u16(&dst, size - 2);
	dst_append(&dst, lsa->id, NODE_ID_LEN);

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		dst_append_int(&dst, attr->type);

		if (attr->keylen) {
			dst_append_u16(&dst, 0x8000 | attr->keylen);
			dst_append(&dst, lsa_attr_key(attr), attr->keylen);
		}

		if (attr->type == LSA_ATTR_TYPE_ADV_PATH && preid != NULL) {
			dst_append_u16(&dst, attr->datalen + NODE_ID_LEN);
			dst_append(&dst, preid, NODE_ID_LEN);
		} else {
			dst_append_u16(&dst, attr->datalen);
		}
		dst_append(&dst, lsa_attr_data(attr), attr->datalen);
	}

	if (size != dst.off) {
		fprintf(stderr, "lsa_serialise: lsa size %d versus "
				"buffer size %d\n", size, dst.off);
		abort();
	}

	return dst.off;
}
