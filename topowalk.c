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
#include <getopt.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_list.h>
#include <stdint.h>
#include <string.h>
#include "conf.h"
#include "util.h"
#include "x509.h"

struct node
{
	struct iv_list_head	list;
	uint8_t			id[20];
	struct iv_list_head	edges;
};

struct edge
{
	struct iv_list_head	list;
	struct node		*to;
	int			type;
};

#define EDGE_TYPE_EPEER		0
#define EDGE_TYPE_CUSTOMER	1
#define EDGE_TYPE_TRANSIT	2
#define EDGE_TYPE_IPEER		3

static struct iv_list_head nodes;
static struct iv_list_head edges;

static struct node *find_node(uint8_t *id)
{
	struct iv_list_head *lh;
	struct node *n;

	iv_list_for_each (lh, &nodes) {
		n = iv_container_of(lh, struct node, list);
		if (!memcmp(n->id, id, 20))
			return n;
	}

	n = malloc(sizeof(*n));
	if (n == NULL)
		return NULL;

	iv_list_add_tail(&n->list, &nodes);
	memcpy(n->id, id, 20);
	INIT_IV_LIST_HEAD(&n->edges);

	return n;
}

static void add_edge(struct node *from, struct node *to, int type)
{
	struct edge *edge;

	edge = malloc(sizeof(*edge));
	if (edge == NULL)
		abort();

	iv_list_add_tail(&edge->list, &from->edges);
	edge->to = to;
	edge->type = type;
}

static void query_node(int fd, struct node *n)
{
	struct sockaddr_in6 addr;
	uint8_t buf[2048];
	int ret;
	socklen_t addrlen;
	int off;

	fprintf(stderr, "- ");
	printhex(stderr, n->id, 20);
	fprintf(stderr, "...");

	buf[0] = 0x20;
	buf[1] = 0x01;
	buf[2] = 0x00;
	buf[3] = 0x2f;
	memcpy(buf + 4, n->id + 4, 12);

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(19275);
	addr.sin6_flowinfo = 0;
	memcpy(&addr.sin6_addr, buf, 16);
	addr.sin6_scope_id = 0;

	ret = sendto(fd, buf, 0, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror(" sendto");
		abort();
	}

	addrlen = sizeof(addr);

	ret = recvfrom(fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &addrlen);
	if (ret < 0) {
		perror(" recvfrom");
		abort();
	}

	if (memcmp(n->id, buf, 20)) {
		fprintf(stderr, " node ID mismatch\n");
		return;
	}

	off = 20;
	while (off + 22 <= ret) {
		struct node *to;
		int type;

		to = find_node(buf + off);
		type = ntohs(*((uint16_t *)(buf + off + 20)));
		off += 22;

		add_edge(n, to, type);
	}

	fprintf(stderr, " done\n");
}

static void scan(uint8_t *initial_id)
{
	int fd;
	struct iv_list_head *lh;

	INIT_IV_LIST_HEAD(&nodes);
	INIT_IV_LIST_HEAD(&edges);

	find_node(initial_id);

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		abort();
	}

	fprintf(stderr, "querying nodes\n");
	iv_list_for_each (lh, &nodes) {
		struct node *n;

		n = iv_container_of(lh, struct node, list);
		query_node(fd, n);
	}
	fprintf(stderr, "\n");

	close(fd);
}

const char *edge_type_name(int type)
{
	switch (type) {
	case EDGE_TYPE_EPEER:
		return "epeer";
	case EDGE_TYPE_CUSTOMER:
		return "customer";
	case EDGE_TYPE_TRANSIT:
		return "transit";
	case EDGE_TYPE_IPEER:
		return "ipeer";
	default:
		return "<unknown>";
	}
}

static void print_nodes(FILE *fp)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		struct iv_list_head *lh2;

		n = iv_container_of(lh, struct node, list);

		fprintf(fp, "node ");
		printhex(fp, n->id, 20);
		fprintf(fp, "\n");

		iv_list_for_each (lh2, &n->edges) {
			struct edge *edge;

			edge = iv_container_of(lh2, struct edge, list);

			fprintf(fp, "  => ");
			printhex(fp, edge->to->id, 20);
			fprintf(fp, " (%s)\n", edge_type_name(edge->type));
		}

		fprintf(fp, "\n");
	}
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
		{ 0, 0, 0, 0, },
	};
	const char *config = "/etc/dvpn.ini";
	struct conf *conf;
	gnutls_x509_privkey_t key;
	uint8_t id[20];

	while (1) {
		int c;

		c = getopt_long(argc, argv, "c:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config = optarg;
			break;

		case '?':
			fprintf(stderr, "syntax: %s [-c <config.ini>]\n",
				argv[0]);
			return 1;

		default:
			abort();
		}
	}

	conf = parse_config(config);
	if (conf == NULL)
		return 1;

	gnutls_global_init();

	if (x509_read_privkey(&key, conf->private_key) < 0)
		return 1;

	x509_get_key_id(id, sizeof(id), key);

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	free_config(conf);

	scan(id);
	print_nodes(stderr);

	return 0;
}
