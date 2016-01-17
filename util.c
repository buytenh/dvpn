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

void v6_global_addr_from_key_id(uint8_t *addr, uint8_t *id, int keylen)
{
	if (keylen < 12)
		abort();

	addr[0] = 0x20;
	addr[1] = 0x01;
	addr[2] = 0x00;
	addr[3] = 0x2f;
	memcpy(addr + 4, id + ((keylen - 12) / 2), 12);
}

void v6_linklocal_addr_from_key_id(uint8_t *addr, uint8_t *id, int keylen)
{
	if (keylen < 14)
		abort();

	addr[0] = 0xfe;
	addr[1] = 0x80;
	memcpy(addr + 2, id + ((keylen - 14) / 2), 14);
}
