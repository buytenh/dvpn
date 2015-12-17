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
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "conf.h"
#include "cspf.h"
#include "spf.h"
#include "x509.h"

struct node
{
	struct iv_list_head	list;
	uint8_t			id[20];
	char			name[128];
	struct iv_list_head	edges;

	struct cspf_node	node;
};

struct edge
{
	struct iv_list_head	list;
	struct node		*to;
	enum peer_type		to_type;

	struct cspf_edge	edge;
};

static struct iv_list_head nodes;

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
	snprintf(n->name, sizeof(n->name),
		 "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:"
		 "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		 id[0],  id[1],  id[2],  id[3],  id[4],
		 id[5],  id[6],  id[7],  id[8],  id[9],
		 id[10], id[11], id[12], id[13], id[14],
		 id[15], id[16], id[17], id[18], id[19]);
	INIT_IV_LIST_HEAD(&n->edges);

	return n;
}

static void
add_edge(struct node *from, struct node *to, enum peer_type to_type)
{
	struct edge *edge;

	edge = malloc(sizeof(*edge));
	if (edge == NULL)
		abort();

	iv_list_add_tail(&edge->list, &from->edges);
	edge->to = to;
	edge->to_type = to_type;
}

static int usecs(struct timeval *t1, struct timeval *t2)
{
	return 1000000LL * (t2->tv_sec - t1->tv_sec) +
		(t2->tv_usec - t1->tv_usec);
}

static void query_node(int fd, struct node *n)
{
	struct sockaddr_in6 addr;
	uint8_t buf[2048];
	int ret;
	struct timeval t1;
	socklen_t addrlen;
	struct timeval t2;
	int off;
	int usec;

	fprintf(stderr, "- %s...", n->name);

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

	gettimeofday(&t1, NULL);

	ret = sendto(fd, buf, 0, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror(" sendto");
		return;
	}

	addrlen = sizeof(addr);

	ret = recvfrom(fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &addrlen);
	if (ret < 0) {
		perror(" recvfrom");
		abort();
	}

	gettimeofday(&t2, NULL);

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

		if (type == 0)
			add_edge(n, to, PEER_TYPE_EPEER);
		else if (type == 1)
			add_edge(n, to, PEER_TYPE_CUSTOMER);
		else if (type == 2)
			add_edge(n, to, PEER_TYPE_TRANSIT);
		else if (type == 3)
			add_edge(n, to, PEER_TYPE_IPEER);
	}

	usec = usecs(&t1, &t2);

	fprintf(stderr, " %d ms\n", usec / 1000);
}

static void scan(uint8_t *initial_id)
{
	int fd;
	struct iv_list_head *lh;

	INIT_IV_LIST_HEAD(&nodes);

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

static void map_node_names(void)
{
	FILE *fp;

	fp = fopen("ids", "r");
	if (fp == NULL)
		return;

	while (!feof(fp)) {
		char id[128];
		char name[128];
		struct iv_list_head *lh;

		if (fscanf(fp, "%s %s", id, name) != 2)
			break;

		iv_list_for_each (lh, &nodes) {
			struct node *n;

			n = iv_container_of(lh, struct node, list);
			if (!strcmp(n->name, id)) {
				strcpy(n->name, name);
				break;
			}
		}
	}

	fclose(fp);
}

static void print_nodes(FILE *fp)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		struct iv_list_head *lh2;

		n = iv_container_of(lh, struct node, list);

		fprintf(fp, "node %s\n", n->name);

		iv_list_for_each (lh2, &n->edges) {
			struct edge *edge;

			edge = iv_container_of(lh2, struct edge, list);

			fprintf(fp, "  => %s (%s)\n", edge->to->name,
				peer_type_name(edge->to_type));
		}

		fprintf(fp, "\n");
	}
}

static struct edge *find_edge(struct node *from, struct node *to)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &from->edges) {
		struct edge *edge;

		edge = iv_container_of(lh, struct edge, list);
		if (edge->to == to)
			return edge;
	}

	return NULL;
}

static int map_peer_type(enum peer_type forward, enum peer_type reverse)
{
	if (forward == PEER_TYPE_IPEER && reverse == PEER_TYPE_IPEER)
		return PEER_TYPE_IPEER;

	if ((forward == PEER_TYPE_CUSTOMER || forward == PEER_TYPE_IPEER) &&
	    (reverse == PEER_TYPE_TRANSIT || reverse == PEER_TYPE_IPEER))
		return PEER_TYPE_CUSTOMER;

	if ((forward == PEER_TYPE_TRANSIT || forward == PEER_TYPE_IPEER) &&
	    (reverse == PEER_TYPE_CUSTOMER || reverse == PEER_TYPE_IPEER))
		return PEER_TYPE_TRANSIT;

	return PEER_TYPE_EPEER;
}

static void prep_cspf(struct spf_context *spf)
{
	struct iv_list_head *lh;

	spf_init(spf);

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		struct iv_list_head *lh2;

		n = iv_container_of(lh, struct node, list);

		n->node.cookie = n;
		cspf_node_add(spf, &n->node);

		iv_list_for_each (lh2, &n->edges) {
			struct edge *e;
			struct edge *rev;

			e = iv_container_of(lh2, struct edge, list);

			rev = find_edge(e->to, n);
			if (rev != NULL) {
				enum peer_type type;

				type = map_peer_type(e->to_type, rev->to_type);
				cspf_edge_add(spf, &e->edge, &n->node,
					      &e->to->node, type, 1);
			}
		}
	}
}

static void print_graphviz(FILE *fp, const char *name)
{
	struct iv_list_head *lh;

	fprintf(fp, "digraph %s {\n", name);
	fprintf(fp, "\trankdir = LR;\n");

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		struct node *p;

		n = iv_list_entry(lh, struct node, list);

		fprintf(fp, "\t\"%s\" [ label = \"%s\\n"
			    "cost: %d\", shape = \"record\" ];\n",
			n->name, n->name, cspf_node_cost(&n->node));

		p = cspf_node_parent(&n->node);
		if (p == NULL)
			continue;

		fprintf(fp, "\t\"%s\" -> \"%s\" [ label = \"%s, %d\" ];\n",
			p->name, n->name,
			peer_type_name(find_edge(p, n)->to_type),
			cspf_node_cost(&n->node) - cspf_node_cost(&p->node));
	}

	fprintf(fp, "}\n");
}

static void print_graphviz_hidden(FILE *fp, const char *name)
{
	struct iv_list_head *lh;

	fprintf(fp, "digraph %s {\n", name);
	fprintf(fp, "\trankdir = LR;\n");

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		struct spf_node *p;

		n = iv_list_entry(lh, struct node, list);

		if (n->node.a.cost != INT_MAX) {
			fprintf(fp, "\t\"%s.a\" [ label = \"%s.a\\n"
				    "cost: %d\", shape = \"record\" ];\n",
				n->name, n->name, n->node.a.cost);
		}

		p = n->node.a.parent;
		if (p != NULL) {
			struct node *pp = p->cookie;
			int isa;

			if (p == &pp->node.a)
				isa = 1;
			else
				isa = 0;

			fprintf(fp, "\t\"%s.%c\" -> \"%s.a\" "
				    "[ label = \"%s, %d\" ];\n",
				pp->name, isa ? 'a' : 'b', n->name,
				peer_type_name(find_edge(pp, n)->to_type),
				n->node.a.cost -
				   (isa ? pp->node.a.cost : pp->node.b.cost));
		}

		if (n->node.b.cost != INT_MAX) {
			fprintf(fp, "\t\"%s.b\" [ label = \"%s.b\\n"
				    "cost: %d\", shape = \"record\" ];\n",
				n->name, n->name, n->node.b.cost);
		}

		p = n->node.b.parent;
		if (p != NULL) {
			struct node *pp = p->cookie;
			int isa;

			if (p == &pp->node.a)
				isa = 1;
			else
				isa = 0;

			fprintf(fp, "\t\"%s.%c\" -> \"%s.b\" "
				    "[ label = \"%s, %d\" ];\n",
				pp->name, isa ? 'a' : 'b', n->name,
				(pp == n) ? "ident" :
				   peer_type_name(find_edge(pp, n)->to_type),
				n->node.b.cost -
				   (isa ? pp->node.a.cost : pp->node.b.cost));
		}
	}

	fprintf(fp, "}\n");
}

static void do_cspfs(void)
{
	struct spf_context spf;
	struct iv_list_head *lh;

	prep_cspf(&spf);

	iv_list_for_each (lh, &nodes) {
		struct node *n;
		char name[256];
		FILE *fp;

		n = iv_list_entry(lh, struct node, list);

		cspf_run(&spf, &n->node);

		snprintf(name, sizeof(name), "cspf_%s.dot", n->name);

		fp = fopen(name, "w");
		if (fp != NULL) {
			fprintf(stderr, "writing %s\n", name);
			print_graphviz(fp, n->name);
			fclose(fp);
		}

		snprintf(name, sizeof(name), "cspf_hidden_%s.dot", n->name);

		fp = fopen(name, "w");
		if (fp != NULL) {
			fprintf(stderr, "writing %s\n", name);
			print_graphviz_hidden(fp, n->name);
			fclose(fp);
		}
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

	map_node_names();
	print_nodes(stderr);

	do_cspfs();

	return 0;
}
