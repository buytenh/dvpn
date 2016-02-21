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
#include "loc_rib.h"
#include "lsa_diff.h"
#include "lsa_print.h"

struct loc_rib_print_info {
	FILE		*fp;
	struct loc_rib	*name_hints;
};

static void loc_rib_print_attr_add(void *_info, struct lsa_attr *a)
{
	struct loc_rib_print_info *info = _info;

	fprintf(info->fp, "+ ");
	lsa_attr_print_type_name(info->fp, 0, a);
	if (a->keylen)
		lsa_attr_print_key(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, " = ");
	lsa_attr_print_data(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, "\n");
}

static void
loc_rib_print_attr_mod(void *_info, struct lsa_attr *a, struct lsa_attr *b)
{
	struct loc_rib_print_info *info = _info;

	fprintf(info->fp, "| ");
	lsa_attr_print_type_name(info->fp, 0, a);
	if (a->keylen)
		lsa_attr_print_key(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, " = ");
	lsa_attr_print_data(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, " -> ");
	lsa_attr_print_data(info->fp, 0, b, info->name_hints);
	fprintf(info->fp, "\n");
}

static void loc_rib_print_attr_del(void *_info, struct lsa_attr *a)
{
	struct loc_rib_print_info *info = _info;

	fprintf(info->fp, "- ");
	lsa_attr_print_type_name(info->fp, 0, a);
	if (a->keylen)
		lsa_attr_print_key(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, " = ");
	lsa_attr_print_data(info->fp, 0, a, info->name_hints);
	fprintf(info->fp, "\n");
}

void loc_rib_print(FILE *fp, struct loc_rib *rib)
{
	struct loc_rib_print_info info = {
		.fp = fp,
		.name_hints = rib,
	};
	struct iv_avl_node *an;
	int count;

	fprintf(fp, "===== BEGIN LOC-RIB DUMP ==============="
		    "======================================\n");

	count = 0;
	iv_avl_tree_for_each (an, &rib->ids) {
		struct loc_rib_id *id;
		struct iv_avl_node *an2;

		id = iv_container_of(an, struct loc_rib_id, an);

		if (count++)
			fprintf(fp, "\n");

		if (id->best != NULL) {
			fprintf(fp, "----- BEST ---------------------------"
				    "-----------------------------------\n");
			fprintf(fp, "cost: %u\n", id->bestcost);
			lsa_print(fp, id->best, rib);
		}

		iv_avl_tree_for_each (an2, &id->lsas) {
			struct loc_rib_lsa_ref *ref;

			ref = iv_container_of(an2, struct loc_rib_lsa_ref, an);
			if (ref->lsa == id->best)
				continue;

			fprintf(fp, "----- ALT ----------------------------"
				    "-----------------------------------\n");

			if (id->best != NULL) {
				fprintf(fp, "cost: %u -> %u\n",
					id->bestcost, ref->cost);

				lsa_diff(id->best, ref->lsa, &info,
					 loc_rib_print_attr_add,
					 loc_rib_print_attr_mod,
					 loc_rib_print_attr_del);
			} else {
				fprintf(fp, "cost: %u\n", ref->cost);
				lsa_print(fp, ref->lsa, rib);
			}
		}

		fprintf(fp, "--------------------------------------"
			    "-----------------------------------\n");
	}

	fprintf(fp, "===== END LOC-RIB DUMP ================="
		    "======================================\n");
}
