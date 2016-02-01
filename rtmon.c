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
#include <ctype.h>
#include <getopt.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <string.h>
#include "conf.h"
#include "cspf.h"
#include "dgp_connect.h"
#include "loc_rib.h"
#include "loc_rib_print.h"
#include "lsa_diff.h"
#include "lsa_print.h"
#include "lsa_type.h"
#include "x509.h"

static uint8_t myid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct rib_listener loc_rib_to_cspf;
static struct dgp_connect dc;
static struct iv_signal sigint;
static struct iv_signal sigusr1;

struct node {
	struct iv_avl_node	an;
	uint8_t			id[NODE_ID_LEN];
	int			refcount;
	struct cspf_node	node;
	struct iv_avl_tree	edges;
};

struct edge {
	struct iv_avl_node	an;
	struct node		*to;
	int			metric;
	enum peer_type		to_type;
	struct cspf_edge	edge;
};

static struct spf_context ctx;
static int num_nodes;
static struct iv_avl_tree nodes;

static int compare_nodes(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct node *a = iv_container_of(_a, struct node, an);
	struct node *b = iv_container_of(_b, struct node, an);

	return memcmp(a->id, b->id, NODE_ID_LEN);
}

static struct node *find_node(uint8_t *id)
{
	struct iv_avl_node *an;

	an = nodes.root;
	while (an != NULL) {
		struct node *node;
		int ret;

		node = iv_container_of(an, struct node, an);

		ret = memcmp(id, node->id, NODE_ID_LEN);
		if (ret == 0)
			return node;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int compare_edges(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct edge *a = iv_container_of(_a, struct edge, an);
	struct edge *b = iv_container_of(_b, struct edge, an);

	return memcmp(a->to->id, b->to->id, NODE_ID_LEN);
}

static struct node *get_node(uint8_t *id)
{
	struct node *node;

	node = find_node(id);
	if (node != NULL)
		return node;

	node = malloc(sizeof(*node));
	if (node == NULL)
		abort();

	memcpy(node->id, id, NODE_ID_LEN);
	node->refcount = 0;

	node->node.id = node->id;
	node->node.cookie = node;
	cspf_node_add(&ctx, &node->node);

	INIT_IV_AVL_TREE(&node->edges, compare_edges);

	num_nodes++;
	iv_avl_tree_insert(&nodes, &node->an);

	return node;
}

static struct edge *find_edge(struct node *from, uint8_t *to)
{
	struct iv_avl_node *an;

	an = from->edges.root;
	while (an != NULL) {
		struct edge *edge;
		int ret;

		edge = iv_container_of(an, struct edge, an);

		ret = memcmp(to, edge->to->id, NODE_ID_LEN);
		if (ret == 0)
			return edge;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
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

static void
register_edge(struct node *from, struct edge *edge, struct edge *back)
{
	enum peer_type type;

	type = map_peer_type(edge->to_type, back->to_type);

	cspf_edge_add(&ctx, &edge->edge, &from->node, &edge->to->node,
		      type, edge->metric);
}

static void
add_edge(struct node *from, uint8_t *_to, int metric, enum peer_type to_type)
{
	struct node *to;
	struct edge *edge;
	struct edge *edge2;

	to = get_node(_to);

	edge = malloc(sizeof(*edge));
	if (edge == NULL)
		abort();

	edge->to = to;
	edge->metric = metric;
	edge->to_type = to_type;

	iv_avl_tree_insert(&from->edges, &edge->an);
	from->refcount++;
	to->refcount++;

	edge2 = find_edge(to, from->id);
	if (edge2 != NULL) {
		register_edge(from, edge, edge2);
		register_edge(to, edge2, edge);
	}
}

static void attr_add(void *_node, struct lsa_attr *attr)
{
	struct node *node = _node;

	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN &&
	    attr->datalen == sizeof(struct lsa_attr_peer)) {
		uint8_t *to;
		struct lsa_attr_peer *peer;
		int metric;

		to = lsa_attr_key(attr);
		peer = lsa_attr_data(attr);
		metric = ntohs(peer->metric);

		if (peer->peer_type == LSA_PEER_TYPE_EPEER)
			add_edge(node, to, metric, PEER_TYPE_EPEER);
		else if (peer->peer_type == LSA_PEER_TYPE_CUSTOMER)
			add_edge(node, to, metric, PEER_TYPE_CUSTOMER);
		else if (peer->peer_type == LSA_PEER_TYPE_TRANSIT)
			add_edge(node, to, metric, PEER_TYPE_TRANSIT);
		else if (peer->peer_type == LSA_PEER_TYPE_IPEER)
			add_edge(node, to, metric, PEER_TYPE_IPEER);
	}
}

static void
unregister_edge(struct node *from, struct edge *edge, struct edge *back)
{
	enum peer_type type;

	type = map_peer_type(edge->to_type, back->to_type);
	cspf_edge_del(&ctx, &edge->edge, &from->node, &edge->to->node, type);
}

static void put_node(struct node *node)
{
	if (!--node->refcount) {
		num_nodes--;
		iv_avl_tree_delete(&nodes, &node->an);
		cspf_node_del(&ctx, &node->node);
		free(node);
	}
}

static void del_edge(struct node *from, uint8_t *to)
{
	struct edge *edge;
	struct edge *edge2;

	edge = find_edge(from, to);

	edge2 = find_edge(edge->to, from->id);
	if (edge2 != NULL) {
		unregister_edge(from, edge, edge2);
		unregister_edge(edge->to, edge2, edge);
	}

	iv_avl_tree_delete(&from->edges, &edge->an);
	put_node(from);
	put_node(edge->to);

	free(edge);
}

static void attr_del(void *_node, struct lsa_attr *attr)
{
	struct node *node = _node;

	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN)
		del_edge(node, lsa_attr_key(attr));
}

static void
attr_mod(void *_node, struct lsa_attr *aattr, struct lsa_attr *battr)
{
	attr_del(_node, aattr);
	attr_add(_node, battr);
}

static void recompute_rtable(void);

static void lsa_add(void *_dummy, struct lsa *a)
{
	lsa_diff(NULL, a, get_node(a->id), attr_add, attr_mod, attr_del);
	recompute_rtable();
}

static void lsa_mod(void *_dummy, struct lsa *a, struct lsa *b)
{
	lsa_diff(a, b, get_node(a->id), attr_add, attr_mod, attr_del);
	recompute_rtable();
}

static void lsa_del(void *_dummy, struct lsa *a)
{
	lsa_diff(a, NULL, get_node(a->id), attr_add, attr_mod, attr_del);
	recompute_rtable();
}

static void rtinit(void)
{
	spf_init(&ctx);

	INIT_IV_AVL_TREE(&nodes, compare_nodes);

	loc_rib_to_cspf.lsa_add = lsa_add;
	loc_rib_to_cspf.lsa_mod = lsa_mod;
	loc_rib_to_cspf.lsa_del = lsa_del;

	loc_rib_listener_register(&loc_rib, &loc_rib_to_cspf);
}

struct rtable_entry {
	uint8_t			dest[16];
	uint8_t			nh[16];
};

struct rtable {
	int			num_entries;
	struct rtable_entry	entry[0];
};

static struct node *find_nexthop(struct node *node, struct node *us)
{
	struct node *a;
	struct node *b;
	struct node *c;

	a = node;

	b = cspf_node_parent(&a->node);
	if (b == NULL)
		return NULL;

	c = cspf_node_parent(&b->node);
	while (c != NULL) {
		a = b;
		b = c;
		c = cspf_node_parent(&c->node);
	}

	if (b != us)
		return NULL;

	return a;
}

static void rtable_add(struct rtable *rt, struct node *dest, struct node *nh)
{
	struct rtable_entry *ent;

	ent = &rt->entry[rt->num_entries++];
	v6_global_addr_from_key_id(ent->dest, dest->id);
	v6_global_addr_from_key_id(ent->nh, nh->id);
}

static int comp(const void *_a, const void *_b)
{
	const struct rtable_entry *a = _a;
	const struct rtable_entry *b = _b;

	return memcmp(a->dest, b->dest, 16);
}

static void rtable_sort(struct rtable *rt)
{
	qsort(rt->entry, rt->num_entries, sizeof(struct rtable_entry), comp);
}

static struct rtable *compute_rtable(void)
{
	struct rtable *rt;
	struct node *from;

	rt = malloc(sizeof(*rt) + num_nodes * sizeof(struct rtable_entry));
	if (rt == NULL)
		return NULL;

	rt->num_entries = 0;

	from = find_node(myid);
	if (from != NULL) {
		struct iv_avl_node *an;

		cspf_run(&ctx, &from->node);

		iv_avl_tree_for_each (an, &nodes) {
			struct node *dest;
			struct node *nh;

			dest = iv_container_of(an, struct node, an);

			nh = find_nexthop(dest, from);
			if (nh != NULL && nh != dest)
				rtable_add(rt, dest, nh);
		}
	}

	rtable_sort(rt);

	return rt;
}

static void print_addr(FILE *fp, uint8_t *addr)
{
	char caddr[64];

	inet_ntop(AF_INET6, addr, caddr, sizeof(caddr));
	fputs(caddr, fp);
}

static void diff_rtable(struct rtable *rta, struct rtable *rtb)
{
	int ia;
	int numa;
	int ib;
	int numb;

	ia = 0;
	numa = (rta != NULL) ? rta->num_entries : 0;
	ib = 0;
	numb = (rtb != NULL) ? rtb->num_entries : 0;

	while (ia < numa && ib < numb) {
		struct rtable_entry *ea = rta->entry + ia;
		struct rtable_entry *eb = rtb->entry + ib;
		int ret;

		ret = memcmp(ea->dest, eb->dest, 16);

		if (ret < 0) {
			printf("- ");
			print_addr(stdout, ea->dest);
			printf(" via ");
			print_addr(stdout, ea->nh);
			printf("\n");

			ia++;
		} else if (ret > 0) {
			printf("+ ");
			print_addr(stdout, eb->dest);
			printf(" via ");
			print_addr(stdout, eb->nh);
			printf("\n");

			ib++;
		} else {
			if (memcmp(ea->nh, eb->nh, 16)) {
				printf("| ");
				print_addr(stdout, ea->dest);
				printf(" via ");
				print_addr(stdout, ea->nh);
				printf(" to ");
				print_addr(stdout, eb->nh);
				printf("\n");
			}

			ia++;
			ib++;
		}
	}

	while (ia < numa) {
		struct rtable_entry *ea = rta->entry + ia;

		printf("- ");
		print_addr(stdout, ea->dest);
		printf(" via ");
		print_addr(stdout, ea->nh);
		printf("\n");

		ia++;
	}

	while (ib < numb) {
		struct rtable_entry *eb = rtb->entry + ib;

		printf("+ ");
		print_addr(stdout, eb->dest);
		printf(" via ");
		print_addr(stdout, eb->nh);
		printf("\n");

		ib++;
	}
}

static struct rtable *rt;

static void recompute_rtable(void)
{
	struct rtable *newrt;

	newrt = compute_rtable();
	diff_rtable(rt, newrt);
	free(rt);
	rt = newrt;
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	dgp_connect_stop(&dc);

	iv_signal_unregister(&sigint);
	iv_signal_unregister(&sigusr1);
}

static void got_sigusr1(void *_dummy)
{
	loc_rib_print(stderr, &loc_rib);
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

	free_config(conf);

	x509_get_key_id(myid, key);

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	iv_init();

	loc_rib_init(&loc_rib);

	rtinit();

	dc.myid = NULL;
	dc.remoteid = myid;
	dc.ifindex = 0;
	dc.loc_rib = &loc_rib;
	dgp_connect_start(&dc);

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	IV_SIGNAL_INIT(&sigusr1);
	sigusr1.signum = SIGUSR1;
	sigusr1.flags = 0;
	sigusr1.cookie = NULL;
	sigusr1.handler = got_sigusr1;
	iv_signal_register(&sigusr1);

	iv_main();

	loc_rib_deinit(&loc_rib);

	iv_deinit();

	return 0;
}
