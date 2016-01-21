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

struct src
{
	uint8_t		*src;
	int		srclen;
	int		off;
};

#define SRC_GET_PTR(_src, _buflen)				\
	({							\
		int off = (_src)->off;				\
		if ((_src)->srclen - off < _buflen)		\
			goto short_read;			\
		(_src)->off += _buflen;				\
		(_src)->src + off;				\
	})

#define SRC_READ(_src, _buf, _buflen)					\
	{								\
		if ((_src)->srclen - (_src)->off < _buflen)		\
			goto short_read;				\
		memcpy(_buf, (_src)->src + (_src)->off, _buflen);	\
		(_src)->off += _buflen;					\
	}

#define SRC_READ_U8(src)			\
	({					\
		uint8_t val;			\
		SRC_READ(src, &val, 1);		\
		val;				\
	})

#define SRC_READ_U16(src)			\
	({					\
		uint8_t val[2];			\
		SRC_READ(src, val, 2);		\
		(val[0] << 8) | val[1];		\
	})

struct lsa *lsa_deserialise(uint8_t *buf, int buflen)
{
	struct lsa *lsa = NULL;
	struct src src;
	int len;
	uint8_t id[32];

	src.src = buf;
	src.srclen = buflen;
	src.off = 0;

	len = SRC_READ_U16(&src);
	if (len + 2 != buflen)
		return NULL;

	SRC_READ(&src, id, sizeof(id));

	lsa = lsa_alloc(id);
	if (lsa == NULL)
		return NULL;

	while (src.off < buflen) {
		int type;
		int val;
		int keylen;
		uint8_t *key;
		int datalen;
		uint8_t *data;

		type = SRC_READ_U8(&src);

		val = SRC_READ_U16(&src);
		if (val & 0x8000) {
			keylen = val & 0x7fff;
			key = SRC_GET_PTR(&src, keylen);

			datalen = SRC_READ_U16(&src) & 0x7fff;
		} else {
			keylen = 0;
			datalen = val & 0x7fff;
		}

		data = SRC_GET_PTR(&src, datalen);

		lsa_attr_add(lsa, type, key, keylen, data, datalen);
	}

	return lsa;

short_read:
	if (lsa != NULL)
		lsa_put(lsa);

	return NULL;
}
