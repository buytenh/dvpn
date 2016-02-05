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

void avl_diff(struct iv_avl_tree *a, struct iv_avl_tree *b,
	      void *cookie,
	      void (*item_add)(void *cookie, struct iv_avl_node *a),
	      void (*item_mod)(void *cookie, struct iv_avl_node *a,
			       struct iv_avl_node *b),
	      void (*item_del)(void *cookie, struct iv_avl_node *a))
{
	struct iv_avl_node *an;
	struct iv_avl_node *bn;

	an = (a != NULL) ? iv_avl_tree_min(a) : NULL;
	bn = (b != NULL) ? iv_avl_tree_min(b) : NULL;

	while (an != NULL && bn != NULL) {
		int ret;

		ret = a->compare(an, bn);
		if (ret < 0) {
			item_del(cookie, an);
			an = iv_avl_tree_next(an);
		} else if (ret > 0) {
			item_add(cookie, bn);
			bn = iv_avl_tree_next(bn);
		} else {
			item_mod(cookie, an, bn);
			an = iv_avl_tree_next(an);
			bn = iv_avl_tree_next(bn);
		}
	}

	while (an != NULL) {
		item_del(cookie, an);
		an = iv_avl_tree_next(an);
	}

	while (bn != NULL) {
		item_add(cookie, bn);
		bn = iv_avl_tree_next(bn);
	}
}

const char *peer_type_name(enum peer_type type)
{
	switch (type) {
	case PEER_TYPE_EPEER:
		return "epeer";
	case PEER_TYPE_CUSTOMER:
		return "customer";
	case PEER_TYPE_TRANSIT:
		return "transit";
	case PEER_TYPE_IPEER:
		return "ipeer";
	default:
		return "<unknown>";
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

void printhex(FILE *fp, const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		fprintf(fp, "%.2x", a[i]);
		if (i < len - 1)
			fprintf(fp, ":");
	}
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
