/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015 Lennert Buytenhek
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
#include "util.h"

int addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family < b->ss_family)
		return -1;

	if (a->ss_family > b->ss_family)
		return 1;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
		const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
		int ret;

		ret = memcmp(&aa->sin_addr, &bb->sin_addr,
			     sizeof(aa->sin_addr));
		if (ret)
			return ret;

		ret = memcmp(&aa->sin_port, &bb->sin_port,
			     sizeof(aa->sin_port));
		if (ret)
			return ret;

		return 0;
	}

	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
		int ret;

		ret = memcmp(&aa->sin6_addr, &bb->sin6_addr,
			     sizeof(aa->sin6_addr));
		if (ret)
			return ret;

		ret = memcmp(&aa->sin6_port, &bb->sin6_port,
			     sizeof(aa->sin6_port));
		if (ret)
			return ret;

		return 0;
	}

	fprintf(stderr, "error comparing addresses of family %d\n",
		a->ss_family);

	abort();
}

void avl_diff(struct iv_avl_tree *a, struct iv_avl_tree *b,
	      void *cookie,
	      void (*item_add)(void *cookie, struct iv_avl_node *a),
	      void (*item_mod)(void *cookie, struct iv_avl_node *a,
			       struct iv_avl_node *b),
	      void (*item_del)(void *cookie, struct iv_avl_node *a))
{
	struct iv_avl_node *an;
	struct iv_avl_node *an2;
	struct iv_avl_node *bn;
	struct iv_avl_node *bn2;

	an = (a != NULL) ? iv_avl_tree_min(a) : NULL;
	bn = (b != NULL) ? iv_avl_tree_min(b) : NULL;

	while (an != NULL && bn != NULL) {
		int ret;

		ret = a->compare(an, bn);
		if (ret < 0) {
			an2 = iv_avl_tree_next(an);
			item_del(cookie, an);
			an = an2;
		} else if (ret > 0) {
			bn2 = iv_avl_tree_next(bn);
			item_add(cookie, bn);
			bn = bn2;
		} else {
			an2 = iv_avl_tree_next(an);
			bn2 = iv_avl_tree_next(bn);
			item_mod(cookie, an, bn);
			an = an2;
			bn = bn2;
		}
	}

	while (an != NULL) {
		an2 = iv_avl_tree_next(an);
		item_del(cookie, an);
		an = an2;
	}

	while (bn != NULL) {
		bn2 = iv_avl_tree_next(bn);
		item_add(cookie, bn);
		bn = bn2;
	}
}

void print_address(FILE *fp, const struct sockaddr *addr)
{
	char dst[128];

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *a4 =
			(const struct sockaddr_in *)addr;

		fprintf(fp, "[%s]:%d",
			inet_ntop(AF_INET, &a4->sin_addr, dst, sizeof(dst)),
			ntohs(a4->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 =
			(const struct sockaddr_in6 *)addr;

		fprintf(fp, "[%s]:%d",
			inet_ntop(AF_INET6, &a6->sin6_addr, dst, sizeof(dst)),
			ntohs(a6->sin6_port));
	} else {
		fprintf(fp, "unknownaf:%d", addr->sa_family);
	}
}

static char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void print_fingerprint(FILE *fp, const uint8_t *id)
{
	int i;
	int j;
	uint32_t val;
	char out[43];

	for (i = 0, j = 0; i < 30; i += 3, j += 4) {
		val = (id[i] << 16) | (id[i + 1] << 8) | id[i + 2];

		out[j] = base64[(val >> 18) & 0x3f];
		out[j + 1] = base64[(val >> 12) & 0x3f];
		out[j + 2] = base64[(val >> 6) & 0x3f];
		out[j + 3] = base64[val & 0x3f];
	}

	val = (id[30] << 16) | (id[31] << 8);
	out[40] = base64[(val >> 18) & 0x3f];
	out[41] = base64[(val >> 12) & 0x3f];
	out[42] = base64[(val >> 6) & 0x3f];

	fwrite(out, 1, sizeof(out), fp);
}

void v6_global_addr_from_key_id(uint8_t *addr, uint8_t *id)
{
	addr[0] = 0x20;
	addr[1] = 0x01;
	addr[2] = 0x00;
	addr[3] = 0x2f;
	memcpy(addr + 4, id + ((NODE_ID_LEN - 12) / 2), 12);
}

void v6_linklocal_addr_from_key_id(uint8_t *addr, uint8_t *id)
{
	addr[0] = 0xfe;
	addr[1] = 0x80;
	memcpy(addr + 2, id + ((NODE_ID_LEN - 14) / 2), 14);
}
