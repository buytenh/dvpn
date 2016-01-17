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

struct dst
{
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

static void dst_append_u8(struct dst *dst, int value)
{
	uint8_t val;

	val = value & 0xff;
	dst_append(dst, &val, 1);
}

static void dst_append_u16(struct dst *dst, int value)
{
	uint8_t val[2];

	val[0] = (value >> 8) & 0xff;
	val[1] = value & 0xff;
	dst_append(dst, val, 2);
}

int lsa_serialise(uint8_t *buf, int buflen, struct lsa *lsa)
{
	struct dst dst;
	struct iv_avl_node *an;
	int len;

	dst.dst = buf;
	dst.dstlen = buflen;
	dst.off = 0;

	dst_append_u16(&dst, 0);
	dst_append(&dst, lsa->id, 32);

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		dst_append_u8(&dst, attr->type);
		if (attr->keylen) {
			dst_append_u16(&dst, 0x8000 | attr->keylen);
			dst_append(&dst, attr->key, attr->keylen);
		}
		dst_append_u16(&dst, attr->datalen);
		dst_append(&dst, attr->data, attr->datalen);
	}

	len = dst.off;

	dst.off = 0;
	dst_append_u16(&dst, len - 2);

	return len;
}
