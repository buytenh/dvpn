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
#include "lsa_print.h"
#include "lsa_type.h"
#include "util.h"

char *lsa_attr_type_name(int type, char *buf, int bufsize)
{
	switch (type) {
	case LSA_ATTR_TYPE_ADV_PATH:
		return "ADV_PATH";
	case LSA_ATTR_TYPE_PEER:
		return "PEER";
	case LSA_ATTR_TYPE_NODE_NAME:
		return "NODE_NAME";
	default:
		snprintf(buf, bufsize, "type-%d", type);
		return buf;
	}
}

void lsa_print(FILE *fp, struct lsa *lsa)
{
	struct iv_avl_node *an;

	fprintf(fp, "-----BEGIN LSA-----\n");

	fprintf(fp, "ID: ");
	printhex(fp, lsa->id, sizeof(lsa->id));
	fprintf(fp, "\n");

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;
		char t[128];

		attr = iv_container_of(an, struct lsa_attr, an);

		fprintf(fp, "* %s",
			lsa_attr_type_name(attr->type, t, sizeof(t)));

		if (attr->keylen) {
			fprintf(fp, "[");
			printhex(fp, attr->key, attr->keylen);
			fprintf(fp, "]");
		}

		fprintf(fp, " = [");
		printhex(fp, attr->data, attr->datalen);
		fprintf(fp, "]\n");
	}

	fprintf(fp, "-----END LSA-----\n");
}
