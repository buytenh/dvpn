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
#include "lsa_deserialise.h"
#include "lsa_type.h"

struct src {
	uint8_t		*src;
	int		srclen;
	int		off;
};

#define SRC_GET_PTR(_src, _buflen)			\
	({						\
		int off = (_src)->off;			\
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

#define SRC_READ_INT(src)				\
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

int lsa_deserialise(struct lsa **lsap, uint8_t *buf, int buflen)
{
	struct lsa *lsa = NULL;
	struct src src;
	int len;
	uint8_t id[NODE_ID_LEN];

	src.src = buf;
	src.srclen = buflen;
	src.off = 0;

	len = SRC_READ_INT(&src);
	if (len == 0) {
		*lsap = NULL;
		return src.off;
	}

	len += src.off;
	if (len > buflen)
		return 0;

	SRC_READ(&src, id, NODE_ID_LEN);

	lsa = lsa_alloc(id);
	if (lsa == NULL)
		return -1;

	while (src.off < len) {
		int type;
		int flags;
		int keylen;
		uint8_t *key;
		int datalen;
		uint8_t *data;

		type = SRC_READ_INT(&src);

		flags = SRC_READ_INT(&src);

		if (flags & LSA_ATTR_FLAG_HAS_KEY) {
			keylen = SRC_READ_INT(&src);
			key = SRC_GET_PTR(&src, keylen);
		} else {
			keylen = 0;
		}

		datalen = SRC_READ_INT(&src);
		data = SRC_GET_PTR(&src, datalen);

		lsa_add_attr(lsa, type, key, keylen, data, datalen);
	}

	*lsap = lsa;

	return src.off;

short_read:
	if (lsa == NULL)
		return 0;

error:
	if (lsa != NULL)
		lsa_put(lsa);

	return -1;
}
