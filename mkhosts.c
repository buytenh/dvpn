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
#include <arpa/inet.h>
#include <ctype.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <string.h>
#include "conf.h"
#include "lsa.h"
#include "lsa_deserialise.h"
#include "lsa_type.h"
#include "util.h"
#include "x509.h"

static uint8_t myid[NODE_ID_LEN];

static void determine_myid(const char *config)
{
	struct conf *conf;
	gnutls_pubkey_t pubkey;

	conf = parse_config(config);
	if (conf == NULL)
		exit(1);

	gnutls_global_init();

	if (read_pubkey(&pubkey, conf->public_key) < 0)
		exit(1);

	free_config(conf);

	get_pubkey_id(myid, pubkey);

	gnutls_pubkey_deinit(pubkey);

	gnutls_global_deinit();
}

static void rcvd_lsa(struct lsa *lsa, const char *suffix)
{
	struct lsa_attr *node_name;
	uint8_t addr[16];
	char dst[128];
	uint8_t *data;
	int i;

	node_name = lsa_find_attr(lsa, LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
	if (node_name == NULL || !node_name->attr_signed)
		return;

	v6_global_addr_from_key_id(addr, lsa->id);
	printf("%s ", inet_ntop(AF_INET6, addr, dst, sizeof(dst)));

	data = lsa_attr_data(node_name);
	for (i = 0; i < node_name->datalen; i++) {
		if (isdnchar(data[i]))
			putchar(data[i]);
		else
			putchar('_');
	}

	printf("%s\n", (suffix != NULL) ? suffix : "");
}

static int read_lsas(int fd, const char *suffix)
{
	int bytes;
	uint8_t buf[65536];

	bytes = 0;
	while (1) {
		int ret;
		int off;

		ret = read(fd, buf + bytes, sizeof(buf) - bytes);
		if (ret < 0) {
			perror("read");
			break;
		}

		if (ret == 0) {
			fprintf(stderr, "connection closed unexpectedly\n");
			break;
		}

		bytes += ret;

		off = 0;
		while (off < bytes) {
			int len;
			struct lsa *lsa;

			len = lsa_deserialise(&lsa, buf + off, bytes - off);
			if (len < 0)
				return -1;

			if (len == 0) {
				if (off == 0 && bytes == sizeof(buf))
					return -1;
				break;
			}

			if (lsa == NULL)
				return 0;

			rcvd_lsa(lsa, suffix);
			lsa_put(lsa);

			off += len;
		}

		bytes -= off;
		memmove(buf, buf + off, bytes);
	}

	return -1;
}

int mkhosts(const char *config, const char *suffix)
{
	int fd;
	struct sockaddr_in6 addr;
	int ret;

	determine_myid(config);

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(173);
	addr.sin6_flowinfo = 0;
	v6_global_addr_from_key_id(addr.sin6_addr.s6_addr, myid);
	addr.sin6_scope_id = 0;

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("connect");
		return 1;
	}

	ret = read_lsas(fd, suffix);
	if (ret < 0)
		return 1;

	close(fd);

	return 0;
}
