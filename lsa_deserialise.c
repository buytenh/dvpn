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
#include <limits.h>
#include <string.h>
#include "lsa_deserialise.h"
#include "lsa_type.h"

struct src {
	uint8_t		*src;
	size_t		srclen;
	size_t		off;
};

#define SRC_GET_PTR(_src, _buflen)			\
	({						\
		size_t off = (_src)->off;		\
		if ((_src)->srclen - off < _buflen)	\
			goto short_read;		\
		(_src)->off += _buflen;			\
		(_src)->src + off;			\
	})

#define SRC_READ(_src, _buf, _buflen)					\
	{								\
		if ((_src)->srclen - (_src)->off < _buflen)		\
			goto short_read;				\
		memcpy(_buf, (_src)->src + (_src)->off, _buflen);	\
		(_src)->off += _buflen;					\
	}

#define SRC_READ_UINT64_T(src)				\
	({						\
		uint8_t val;				\
		int cnt;				\
		uint64_t v;				\
							\
		SRC_READ(src, &val, 1);			\
		if (val == 0x80)			\
			goto error;			\
							\
		cnt = 0;				\
		v = val & 0x7f;				\
		while (val & 0x80) {			\
			if (++cnt == 10)		\
				goto error;		\
			SRC_READ(src, &val, 1);		\
			v = (v << 7) | (val & 0x7f);	\
		}					\
							\
		v;					\
	})

#define SRC_READ_INT(src)				\
	({						\
		uint64_t v;				\
							\
		v = SRC_READ_UINT64_T(src);		\
		if (v > INT_MAX)			\
			goto error;			\
							\
		(int)v;					\
	})

#define SRC_READ_SIZE_T(src)				\
	({						\
		uint64_t v;				\
							\
		v = SRC_READ_UINT64_T(src);		\
		if (v > SIZE_MAX)			\
			goto error;			\
							\
		(size_t)v;				\
	})

static int lsa_deserialise_attr_set(struct lsa *lsa, struct lsa_attr_set *dst,
				    struct src *src, int maxdepth)
{
	while (src->off < src->srclen) {
		int type;
		int flags;
		size_t keylen;
		uint8_t *key;
		size_t datalen;
		uint8_t *data;
		int sign;

		type = SRC_READ_INT(src);

		flags = SRC_READ_INT(src);

		if (flags & LSA_ATTR_FLAG_HAS_KEY) {
			keylen = SRC_READ_SIZE_T(src);
			key = SRC_GET_PTR(src, keylen);
		} else {
			keylen = 0;
		}

		datalen = SRC_READ_SIZE_T(src);
		data = SRC_GET_PTR(src, datalen);

		sign = !!(flags & LSA_ATTR_FLAG_SIGNED);

		if (flags & LSA_ATTR_FLAG_DATA_IS_TLV) {
			struct lsa_attr_set *set;
			struct src srcdata;

			if (maxdepth == 0)
				return -1;

			set = lsa_attr_set_add_attr_set(lsa, dst, type, sign,
							key, keylen);
			if (set == NULL)
				return -1;

			srcdata.src = data;
			srcdata.srclen = datalen;
			srcdata.off = 0;
			if (lsa_deserialise_attr_set(lsa, set, &srcdata,
						     maxdepth - 1) < 0) {
				return -1;
			}
		} else {
			if (lsa_attr_set_add_attr(lsa, dst, type, sign,
						  key, keylen,
						  data, datalen) < 0) {
				return -1;
			}
		}
	}

	return 0;

short_read:
error:
	return -1;
}

ssize_t lsa_deserialise(struct lsa **lsap, uint8_t *buf, size_t buflen)
{
	struct lsa *lsa = NULL;
	struct src src;
	size_t len;
	uint8_t id[NODE_ID_LEN];

	src.src = buf;
	src.srclen = buflen;
	src.off = 0;

	len = SRC_READ_SIZE_T(&src);
	if (len == 0) {
		*lsap = NULL;
		return src.off;
	}

	if (len > SSIZE_MAX - src.off)
		return -1;

	len += src.off;
	if (len > buflen)
		return 0;

	src.srclen = len;

	SRC_READ(&src, id, NODE_ID_LEN);

	lsa = lsa_alloc(id);
	if (lsa == NULL)
		return -1;

	if (lsa_deserialise_attr_set(lsa, &lsa->root, &src, 8) < 0)
		goto error;

	*lsap = lsa;

	return src.off;

short_read:
	return 0;

error:
	if (lsa != NULL)
		lsa_put(lsa);

	return -1;
}
