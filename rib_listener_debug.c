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
	char t[128];

	printf("%s: attr add: %s", (char *)cookie,
	       lsa_attr_type_name(attr->type, t, sizeof(t)));

	if (attr->keylen) {
		printf("[");
		printhex(stdout, attr->key, attr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, attr->data, attr->datalen);
	printf("]\n");
}

static void
attr_mod(void *cookie, struct lsa_attr *aattr, struct lsa_attr *battr)
{
	char t[128];

	printf("%s: attr mod: %s", (char *)cookie,
	       lsa_attr_type_name(aattr->type, t, sizeof(t)));

	if (aattr->keylen) {
		printf("[");
		printhex(stdout, aattr->key, aattr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, aattr->data, aattr->datalen);
	printf("] -> [");
	printhex(stdout, battr->data, battr->datalen);
	printf("]\n");
}

static void attr_del(void *cookie, struct lsa_attr *attr)
{
	char t[128];

	printf("%s: attr del: %s", (char *)cookie,
	       lsa_attr_type_name(attr->type, t, sizeof(t)));

	if (attr->keylen) {
		printf("[");
		printhex(stdout, attr->key, attr->keylen);
		printf("]");
	}

	printf(" = [");
	printhex(stdout, attr->data, attr->datalen);
	printf("]\n");
}

static void lsa_add(void *cookie, struct lsa *a)
{
	printf("%s: lsa add [", (char *)cookie);
	printhex(stdout, a->id, 32);
	printf("]\n");

	lsa_diff(NULL, a, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_mod(void *cookie, struct lsa *a, struct lsa *b)
{
	printf("%s: lsa mod [", (char *)cookie);
	printhex(stdout, a->id, 32);
	printf("]\n");

	lsa_diff(a, b, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

static void lsa_del(void *cookie, struct lsa *a)
{
	printf("%s: lsa del [", (char *)cookie);
	printhex(stdout, a->id, 32);
	printf("]\n");

	lsa_diff(a, NULL, cookie, attr_add, attr_mod, attr_del);

	printf("\n");
}

struct rib_listener *debug_listener_new(char *name)
{
	struct rib_listener *rl;

	rl = malloc(sizeof(*rl));
	if (rl == NULL)
		return NULL;

	rl->cookie = (void *)strdup(name);
	rl->lsa_add = lsa_add;
	rl->lsa_mod = lsa_mod;
	rl->lsa_del = lsa_del;

	return rl;
}

void debug_listener_set_name(struct rib_listener *rl, uint8_t *name, int len)
{
	if (strlen(rl->cookie) != len || memcmp(rl->cookie, name, len)) {
		free(rl->cookie);

		rl->cookie = malloc(len + 1);
		if (rl->cookie == NULL)
			abort();

		memcpy(rl->cookie, name, len);
		((uint8_t *)rl->cookie)[len] = 0;
	}
}

void debug_listener_free(struct rib_listener *rl)
{
	free(rl->cookie);
	free(rl);
}
