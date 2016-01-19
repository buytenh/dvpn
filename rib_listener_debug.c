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
#include "lsa_diff.h"
#include "lsa_print.h"
#include "rib_listener.h"
#include "rib_listener_debug.h"
#include "util.h"

static void attr_add(void *cookie, struct lsa_attr *attr)
{
	struct rib_listener_debug *rl = cookie;
	char t[128];

	printf("%s: attr add: %s", rl->name,
	       lsa_attr_type_name(attr->type, t, sizeof(t)));

	if (attr->keylen) {
		printf("[");
		printhex(stdout, lsa_attr_key(attr), attr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, lsa_attr_data(attr), attr->datalen);
	printf("]\n");
}

static void
attr_mod(void *cookie, struct lsa_attr *aattr, struct lsa_attr *battr)
{
	struct rib_listener_debug *rl = cookie;
	char t[128];

	printf("%s: attr mod: %s", rl->name,
	       lsa_attr_type_name(aattr->type, t, sizeof(t)));

	if (aattr->keylen) {
		printf("[");
		printhex(stdout, lsa_attr_key(aattr), aattr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, lsa_attr_data(aattr), aattr->datalen);
	printf("] -> [");
	printhex(stdout, lsa_attr_data(battr), battr->datalen);
	printf("]\n");
}

static void attr_del(void *cookie, struct lsa_attr *attr)
{
	struct rib_listener_debug *rl = cookie;
	char t[128];

	printf("%s: attr del: %s", rl->name,
	       lsa_attr_type_name(attr->type, t, sizeof(t)));

	if (attr->keylen) {
		printf("[");
		printhex(stdout, lsa_attr_key(attr), attr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, lsa_attr_data(attr), attr->datalen);
	printf("]\n");
}

static void lsa_add(void *cookie, struct lsa *a)
{
	struct rib_listener_debug *rl = cookie;

	printf("%s: lsa add [", rl->name);
	printhex(stdout, a->id, 32);
	printf("]\n");

	lsa_diff(NULL, a, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_mod(void *cookie, struct lsa *a, struct lsa *b)
{
	struct rib_listener_debug *rl = cookie;

	printf("%s: lsa mod [", rl->name);
	printhex(stdout, a->id, 32);
	printf("]\n");

	lsa_diff(a, b, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_del(void *cookie, struct lsa *a)
{
	struct rib_listener_debug *rl = cookie;

	printf("%s: lsa del [", rl->name);
	printhex(stdout, a->id, 32);
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
