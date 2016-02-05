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

#ifndef __UTIL_H
#define __UTIL_H

#include <arpa/inet.h>
#include <iv_avl.h>
#include <stdint.h>

#define NODE_ID_LEN	32

enum peer_type {
	PEER_TYPE_INVALID = 0,
	PEER_TYPE_EPEER = 1,
	PEER_TYPE_CUSTOMER = 2,
	PEER_TYPE_TRANSIT = 3,
	PEER_TYPE_IPEER = 4,
};

int addrcmp(const struct sockaddr_storage *a,
	    const struct sockaddr_storage *b);
void avl_diff(struct iv_avl_tree *a, struct iv_avl_tree *b, void *cookie,
	      void (*item_add)(void *cookie, struct iv_avl_node *a),
	      void (*item_mod)(void *cookie, struct iv_avl_node *a,
			       struct iv_avl_node *b),
	      void (*item_del)(void *cookie, struct iv_avl_node *a));
const char *peer_type_name(enum peer_type type);
void print_address(FILE *fp, const struct sockaddr *addr);
void printhex(FILE *fp, const uint8_t *a, int len);
void v6_global_addr_from_key_id(uint8_t *addr, uint8_t *id);
void v6_linklocal_addr_from_key_id(uint8_t *addr, uint8_t *id);


#endif
