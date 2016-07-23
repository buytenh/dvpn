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

/*
 * Alphabet: 0123456789bcdfghjklmnpqrstuvwxyz
 * Excluded characters: a, e, i, o
 */
static int8_t base32idx[] = {
	-1, 10, 11, 12, -1, 13, 14, 15, -1, 16, 17, 18, 19,
	20, -1, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

static int base32char(char c)
{
	if (c >= '0' && c <= '9')
		return 0 + (c - '0');

	if (c >= 'A' && c <= 'Z')
		return base32idx[c - 'A'];

	if (c >= 'a' && c <= 'z')
		return base32idx[c - 'a'];

	return -1;
}

int parse_base32_fingerprint(uint8_t *id, const char *fp)
{
	int i;
	int j;

	memset(id, 0, NODE_ID_LEN);
	for (i = 0, j = 0; i < 52; i++, j += 5) {
		int v;
		int byte;

		v = base32char(fp[i]);
		if (v < 0)
			return -1;

		v <<= j & 7;

		byte = j >> 3;
		id[byte] |= v & 0xff;
		if ((v & 0xff00) && byte + 1 < NODE_ID_LEN)
			id[byte + 1] |= v >> 8;
	}

	return 0;
}

int parse_hostname_fingerprint(uint8_t *id, const char *hostname)
{
	while (strlen(hostname) > 56) {
		const char *c;

		if (!strncmp(hostname, "z2bq", 4) &&
		    !parse_base32_fingerprint(id, hostname + 4) &&
		    hostname[56] == '.') {
			return 0;
		}

		c = strchr(hostname, '.');
		if (c == NULL)
			return -1;

		hostname = c + 1;
	}

	return -1;
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

static char base32[] =
	"0123456789bcdfghjklmnpqrstuvwxyz";

void print_fingerprint(FILE *fp, const uint8_t *id)
{
	int i;
	int j;
	char out[52];

	for (i = 0, j = 0; i < 52; i++, j += 5) {
		int byte;
		int val;

		byte = j >> 3;
		val = id[byte];
		if (byte + 1 < NODE_ID_LEN)
			val |= id[byte + 1] << 8;

		out[i] = base32[(val >> (j & 7)) & 0x1f];
	}

	fwrite(out, 1, sizeof(out), fp);
}

void timespec_add_ms(struct timespec *ts, int minms, int maxms)
{
	int ms;

	ms = minms;
	ms += ((maxms - minms) * ((long long)random())) / RAND_MAX;

	ts->tv_sec += ms / 1000;
	ts->tv_nsec += 1000000 * (ms % 1000);
	if (ts->tv_nsec >= 1000000000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

void v6_global_addr_from_key_id(uint8_t *addr, const uint8_t *id)
{
	addr[0] = 0x20;
	addr[1] = 0x01;
	addr[2] = 0x00;
	addr[3] = 0x2f;
	memcpy(addr + 4, id + ((NODE_ID_LEN - 12) / 2), 12);
}

void v6_linklocal_addr_from_key_id(uint8_t *addr, const uint8_t *id)
{
	addr[0] = 0xfe;
	addr[1] = 0x80;
	memcpy(addr + 2, id + ((NODE_ID_LEN - 14) / 2), 14);
}
