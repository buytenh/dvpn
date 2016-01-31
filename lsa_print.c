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
#include <ctype.h>
#include <iv_list.h>
#include "loc_rib.h"
#include "lsa_print.h"
#include "lsa_type.h"
#include "util.h"

static char *lsa_attr_type_name(int type, char *buf, int bufsize)
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

void lsa_attr_print_type_name(FILE *fp, struct lsa_attr *attr)
{
	char t[128];

	fputs(lsa_attr_type_name(attr->type, t, sizeof(t)), fp);
}

static void print_node_name(FILE *fp, struct lsa_attr *attr)
{
	uint8_t *data = lsa_attr_data(attr);
	int i;

	for (i = 0; i < attr->datalen; i++) {
		if (isalnum(data[i]))
			fputc(data[i], fp);
		else
			fputc('_', fp);
	}
}

static void print_id_name(FILE *fp, uint8_t *id, struct loc_rib *name_hints)
{
	if (name_hints != NULL) {
		struct loc_rib_id *rid;

		rid = loc_rib_find_id(name_hints, id);
		if (rid != NULL && rid->best != NULL) {
			struct lsa_attr *attr;

			attr = lsa_attr_find(rid->best,
					     LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
			if (attr != NULL) {
				print_node_name(fp, attr);
				return;
			}
		}
	}

	printhex(fp, id, NODE_ID_LEN);
}

void lsa_attr_print_key(FILE *fp, struct lsa_attr *attr,
			struct loc_rib *name_hints)
{
	fprintf(fp, "[");
	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN) {
		print_id_name(fp, lsa_attr_key(attr), name_hints);
	} else {
		printhex(fp, lsa_attr_key(attr), attr->keylen);
	}
	fprintf(fp, "]");
}

void lsa_attr_print_data(FILE *fp, struct lsa_attr *attr,
			 struct loc_rib *name_hints)
{
	fprintf(fp, "[");
	if (attr->type == LSA_ATTR_TYPE_ADV_PATH &&
	    (attr->datalen % NODE_ID_LEN) == 0) {
		uint8_t *data = lsa_attr_data(attr);
		int i;

		for (i = 0; i < attr->datalen; i += NODE_ID_LEN) {
			if (i)
				fputc(' ', fp);
			print_id_name(fp, data + i, name_hints);
		}
	} else if (attr->type == LSA_ATTR_TYPE_NODE_NAME) {
		print_node_name(fp, attr);
	} else {
		printhex(fp, lsa_attr_data(attr), attr->datalen);
	}
	fprintf(fp, "]");
}

void lsa_print(FILE *fp, struct lsa *lsa, struct loc_rib *name_hints)
{
	struct iv_avl_node *an;

	fprintf(fp, "LSA [");
	printhex(fp, lsa->id, NODE_ID_LEN / 2);
	fprintf(fp, ":\n     ");
	printhex(fp, lsa->id + (NODE_ID_LEN / 2), NODE_ID_LEN / 2);
	fprintf(fp, "]\n");

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		fprintf(fp, "* ");
		lsa_attr_print_type_name(fp, attr);
		if (attr->keylen)
			lsa_attr_print_key(fp, attr, name_hints);
		fprintf(fp, " = ");
		lsa_attr_print_data(fp, attr, name_hints);
		fprintf(fp, "\n");
	}
}
