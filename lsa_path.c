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

int lsa_path_contains(struct lsa_attr *attr, const uint8_t *id)
{
	void *data;
	size_t i;

	if (attr->type != LSA_ATTR_TYPE_ADV_PATH)
		abort();

	data = lsa_attr_data(attr);
	for (i = 0; i < attr->datalen; i += NODE_ID_LEN) {
		if (!memcmp(data + i, id, NODE_ID_LEN))
			return 1;
	}

	return 0;
}
