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

static char *
lsa_attr_type_name(int parent_type, int type, char *buf, int bufsize)
{
	if (parent_type == 0) {
		switch (type) {
		case LSA_ATTR_TYPE_ADV_PATH:
			return "ADV_PATH";
		case LSA_ATTR_TYPE_PEER:
			return "PEER";
		case LSA_ATTR_TYPE_NODE_NAME:
			return "NODE_NAME";
		case LSA_ATTR_TYPE_VERSION:
			return "VERSION";
		case LSA_ATTR_TYPE_PUBKEY:
			return "PUBKEY";
		case LSA_ATTR_TYPE_SIGNATURE:
			return "SIGNATURE";
		}
	}

	if (parent_type == LSA_ATTR_TYPE_PEER) {
		switch (type) {
		case LSA_PEER_ATTR_TYPE_METRIC:
			return "metric";
		case LSA_PEER_ATTR_TYPE_PEER_FLAGS:
			return "flags";
		}
	}

	snprintf(buf, bufsize, "type-%d-%d", parent_type, type);

	return buf;
}

void lsa_attr_print_type_name(FILE *fp, int parent_type, struct lsa_attr *attr)
{
	char t[128];

	fputs(lsa_attr_type_name(parent_type, attr->type, t, sizeof(t)), fp);
	if (attr->attr_signed)
		fprintf(fp, "(signed)");
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

int lsa_print_id_name(FILE *fp, uint8_t *id, struct loc_rib *name_hints)
{
	if (name_hints != NULL) {
		struct loc_rib_id *rid;

		rid = loc_rib_find_id(name_hints, id);
		if (rid != NULL && rid->best != NULL) {
			struct lsa_attr *attr;

			attr = lsa_find_attr(rid->best,
					     LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
			if (attr != NULL) {
				print_node_name(fp, attr);
				return 1;
			}
		}
	}

	print_fingerprint(fp, id);

	return 0;
}

void lsa_attr_print_key(FILE *fp, int parent_type, struct lsa_attr *attr,
			struct loc_rib *name_hints)
{
	fprintf(fp, "[");
	if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_PEER &&
	    attr->keylen == NODE_ID_LEN) {
		lsa_print_id_name(fp, lsa_attr_key(attr), name_hints);
	} else {
		printhex(fp, lsa_attr_key(attr), attr->keylen);
	}
	fprintf(fp, "]");
}

void lsa_attr_print_data(FILE *fp, int parent_type, struct lsa_attr *attr,
			 struct loc_rib *name_hints)
{
	if (parent_type == 0 || attr->data_is_attr_set)
		fprintf(fp, "[");

	if (attr->data_is_attr_set) {
		int type;
		struct lsa_attr_set *set;
		int count;
		struct iv_avl_node *an;

		if (parent_type == 0)
			type = attr->type;
		else
			type = -1;

		set = lsa_attr_data(attr);

		count = 0;
		iv_avl_tree_for_each (an, &set->attrs) {
			struct lsa_attr *child;

			child = iv_container_of(an, struct lsa_attr, an);

			if (count++)
				fprintf(fp, " ");
			lsa_attr_print_type_name(fp, type, child);
			if (child->keylen)
				lsa_attr_print_key(fp, type, child, name_hints);
			fprintf(fp, "=");
			lsa_attr_print_data(fp, type, child, name_hints);
		}
	} else if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_ADV_PATH &&
	    (attr->datalen % NODE_ID_LEN) == 0) {
		uint8_t *data = lsa_attr_data(attr);
		size_t i;

		for (i = 0; i < attr->datalen; i += NODE_ID_LEN) {
			if (i)
				fputc(' ', fp);
			lsa_print_id_name(fp, data + i, name_hints);
		}
	} else if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_NODE_NAME) {
		print_node_name(fp, attr);
	} else if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_VERSION) {
		printhex(fp, lsa_attr_data(attr), attr->datalen);
	} else if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_PUBKEY) {
		fprintf(fp, "<pubkey>");
	} else if (parent_type == 0 && attr->type == LSA_ATTR_TYPE_SIGNATURE) {
		fprintf(fp, "<signature>");
	} else if (parent_type == LSA_ATTR_TYPE_PEER &&
		   attr->type == LSA_PEER_ATTR_TYPE_METRIC &&
		   attr->datalen == 2) {
		uint16_t *metric = lsa_attr_data(attr);

		fprintf(fp, "%d", ntohs(*metric));
	} else if (parent_type == LSA_ATTR_TYPE_PEER &&
		   attr->type == LSA_PEER_ATTR_TYPE_PEER_FLAGS &&
		   attr->datalen == 1) {
		uint8_t *peer_flags = lsa_attr_data(attr);
		uint8_t ct;

		ct = *peer_flags &
			(LSA_PEER_FLAGS_CUSTOMER | LSA_PEER_FLAGS_TRANSIT);

		if (ct == 0)
			fprintf(fp, "epeer");
		else if (ct == LSA_PEER_FLAGS_CUSTOMER)
			fprintf(fp, "customer");
		else if (ct == LSA_PEER_FLAGS_TRANSIT)
			fprintf(fp, "transit");
		else if (ct == (LSA_PEER_FLAGS_CUSTOMER |
				LSA_PEER_FLAGS_TRANSIT))
			fprintf(fp, "ipeer");
		else
			fprintf(fp, "%d", ct);
	} else {
		printhex(fp, lsa_attr_data(attr), attr->datalen);
	}

	if (parent_type == 0 || attr->data_is_attr_set)
		fprintf(fp, "]");
}

void lsa_print(FILE *fp, struct lsa *lsa, struct loc_rib *name_hints)
{
	struct iv_avl_node *an;

	fprintf(fp, "LSA [");
	print_fingerprint(fp, lsa->id);
	fprintf(fp, "]\n");

	iv_avl_tree_for_each (an, &lsa->root.attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		fprintf(fp, "* ");
		lsa_attr_print_type_name(fp, 0, attr);
		if (attr->keylen)
			lsa_attr_print_key(fp, 0, attr, name_hints);
		fprintf(fp, " = ");
		lsa_attr_print_data(fp, 0, attr, name_hints);
		fprintf(fp, "\n");
	}
}
