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
#include <string.h>
#include "lsa.h"
#include "lsa_type.h"

void lsa_path_prepend(struct lsa *lsa, uint8_t *id)
{
	struct lsa_attr *attr;

	if (lsa->refcount != 1)
		abort();

	attr = lsa_attr_find(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr != NULL) {
		uint8_t *newdata;

		newdata = malloc(attr->datalen + 32);
		if (newdata == NULL)
			abort();

		memcpy(newdata, id, 32);
		memcpy(newdata + 32, attr->data, attr->datalen);

		free(attr->data);
		attr->data = newdata;
		attr->datalen += 32;
	} else {
		lsa_attr_add(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0, id, 32);
	}
}
