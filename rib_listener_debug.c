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
#include <time.h>
#include "lsa_diff.h"
#include "lsa_print.h"
#include "rib_listener.h"
#include "rib_listener_debug.h"
#include "util.h"

static void print_listener_name(struct rib_listener_debug *rl)
{
	if (rl->name != NULL)
		printf("%s: ", rl->name);
}

static void attr_add(void *cookie, struct lsa_attr *attr)
{
	struct rib_listener_debug *rl = cookie;

	print_listener_name(rl);
	printf("attr add: ");
	lsa_attr_print_type_name(stdout, 0, attr);
	if (attr->keylen)
		lsa_attr_print_key(stdout, 0, attr, rl->name_hints);
	printf(" = ");
	lsa_attr_print_data(stdout, 0, attr, rl->name_hints);
	printf("\n");
}

static void
attr_mod(void *cookie, struct lsa_attr *aattr, struct lsa_attr *battr)
{
	struct rib_listener_debug *rl = cookie;

	print_listener_name(rl);
	printf("attr mod: ");
	lsa_attr_print_type_name(stdout, 0, aattr);
	if (aattr->keylen)
		lsa_attr_print_key(stdout, 0, aattr, rl->name_hints);
	printf(" = ");
	lsa_attr_print_data(stdout, 0, aattr, rl->name_hints);
	printf(" -> ");
	lsa_attr_print_data(stdout, 0, battr, rl->name_hints);
	printf("\n");
}

static void attr_del(void *cookie, struct lsa_attr *attr)
{
	struct rib_listener_debug *rl = cookie;

	print_listener_name(rl);
	printf("attr del: ");
	lsa_attr_print_type_name(stdout, 0, attr);
	if (attr->keylen)
		lsa_attr_print_key(stdout, 0, attr, rl->name_hints);
	printf(" = ");
	lsa_attr_print_data(stdout, 0, attr, rl->name_hints);
	printf("\n");
}

static void print_timestamp(void)
{
	time_t now;
	struct tm tm;
	char buf[64];
	int len;

	now = time(NULL);
	gmtime_r(&now, &tm);
	asctime_r(&tm, buf);

	len = strlen(buf);
	if (len)
		buf[len - 1] = 0;

	printf("===== %s UTC =====\n", buf);
}

static void lsa_add(void *cookie, struct lsa *a, uint32_t cost)
{
	struct rib_listener_debug *rl = cookie;

	print_timestamp();
	print_listener_name(rl);
	printf("lsa add: [");
	if (lsa_print_id_name(stdout, a->id, rl->name_hints)) {
		printf("(");
		printhex(stdout, a->id, NODE_ID_LEN);
		printf(")");
	}
	printf("]\n");

	lsa_diff(NULL, a, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_mod(void *cookie, struct lsa *a, uint32_t acost,
		    struct lsa *b, uint32_t bcost)
{
	struct rib_listener_debug *rl = cookie;

	print_timestamp();
	print_listener_name(rl);
	printf("lsa mod: [");
	if (lsa_print_id_name(stdout, a->id, rl->name_hints)) {
		printf("(");
		printhex(stdout, a->id, NODE_ID_LEN);
		printf(")");
	}
	printf("]\n");

	lsa_diff(a, b, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_del(void *cookie, struct lsa *a, uint32_t cost)
{
	struct rib_listener_debug *rl = cookie;

	print_timestamp();
	print_listener_name(rl);
	printf("lsa del: [");
	if (lsa_print_id_name(stdout, a->id, rl->name_hints)) {
		printf("(");
		printhex(stdout, a->id, NODE_ID_LEN);
		printf(")");
	}
	printf("]\n");

	lsa_diff(a, NULL, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

void rib_listener_debug_init(struct rib_listener_debug *rl)
{
	rl->rl.cookie = rl;
	rl->rl.lsa_add = lsa_add;
	rl->rl.lsa_mod = lsa_mod;
	rl->rl.lsa_del = lsa_del;
}

void rib_listener_debug_deinit(struct rib_listener_debug *rl)
{
}
