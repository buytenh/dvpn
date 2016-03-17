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
#include <iv.h>
#include <iv_signal.h>
#include <string.h>
#include "conf.h"
#include "dgp_connect.h"
#include "loc_rib.h"
#include "lsa.h"
#include "lsa_peer.h"
#include "lsa_type.h"
#include "util.h"
#include "x509.h"

static uint8_t myid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct iv_timer dump_timer;
static struct rib_listener rib_listener;
static struct dgp_connect dc;
static struct iv_signal sigint;

static int __get_lsa_node_name(char *buf, size_t buflen, struct lsa *lsa)
{
	struct lsa_attr *attr;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
	if (attr != NULL && attr->attr_signed) {
		uint8_t *data;
		size_t len;
		int i;

		data = lsa_attr_data(attr);

		len = attr->datalen;
		if (len > buflen - 1)
			len = buflen - 1;

		for (i = 0; i < len; i++)
			buf[i] = isalnum(data[i]) ? data[i] : '_';
		buf[len] = 0;

		return 1;
	}

	return 0;
}

static void hex_node_name(char *buf, size_t buflen, const uint8_t *id)
{
	int i;
	char hexid[2 * NODE_ID_LEN + 16];

	for (i = 0; i < NODE_ID_LEN; i++)
		sprintf(hexid + 2 * i, "%.2x", id[i]);

	strncpy(buf, hexid, buflen);
}

static void get_lsa_node_name(char *buf, size_t buflen, struct lsa *lsa)
{
	if (!__get_lsa_node_name(buf, buflen, lsa))
		hex_node_name(buf, buflen, lsa->id);
}

static struct lsa *find_lsa(const uint8_t *id)
{
	struct loc_rib_id *rid;

	rid = loc_rib_find_id(&loc_rib, id);
	if (rid == NULL)
		return NULL;

	return rid->best;
}

static void print_edge(FILE *fp, struct lsa *from, uint8_t *toid)
{
	char fromname[128];
	struct lsa_peer_info forward;
	struct lsa *to;
	char toname[128];
	struct lsa_peer_info reverse;

	get_lsa_node_name(fromname, sizeof(fromname), from);

	if (lsa_get_peer_info(&forward, from, toid) < 0) {
		forward.metric = -1;
		forward.flags = 0;
	}

	to = find_lsa(toid);
	if (to == NULL) {
		hex_node_name(toname, sizeof(toname), toid);
		fprintf(fp, "\t\"%s\" [ color=red fontcolor=red ]\n", toname);
		fprintf(fp, "\t\"%s\" -> \"%s\" [ color=red fontcolor=red "
			    "label=\"%d\" ];\n",
			fromname, toname, forward.metric);
		return;
	}

	if (memcmp(from->id, toid, NODE_ID_LEN) >= 0)
		return;

	get_lsa_node_name(toname, sizeof(toname), to);

	if (lsa_get_peer_info(&reverse, to, from->id) < 0) {
		reverse.metric = -1;
		reverse.flags = 0;
	}

	if (forward.flags == 0 && reverse.flags == 0) {
		fprintf(fp, "\t\"%s\" -> \"%s\" ", fromname, toname);
		fprintf(fp, "[ constraint=false dir=none ");
		fprintf(fp, "label=\"%d", forward.metric);
		if (forward.metric != reverse.metric)
			fprintf(fp, "/%d", reverse.metric);
		fprintf(fp, "\" ];\n");
	} else if (forward.flags == LSA_PEER_FLAGS_CUSTOMER &&
		   reverse.flags == LSA_PEER_FLAGS_TRANSIT) {
		fprintf(fp, "\t\"%s\" -> \"%s\" ", toname, fromname);
		fprintf(fp, "[ label=\"%d", forward.metric);
		if (forward.metric != reverse.metric)
			fprintf(fp, "/%d", reverse.metric);
		fprintf(fp, "\" ];\n");
	} else if (forward.flags == LSA_PEER_FLAGS_TRANSIT &&
		   reverse.flags == LSA_PEER_FLAGS_CUSTOMER) {
		fprintf(fp, "\t\"%s\" -> \"%s\" ", fromname, toname);
		fprintf(fp, "[ label=\"%d", reverse.metric);
		if (reverse.metric != forward.metric)
			fprintf(fp, "/%d", forward.metric);
		fprintf(fp, "\" ];\n");
	} else if (forward.flags == (LSA_PEER_FLAGS_CUSTOMER |
				     LSA_PEER_FLAGS_TRANSIT) &&
		   reverse.flags == (LSA_PEER_FLAGS_CUSTOMER |
				     LSA_PEER_FLAGS_TRANSIT)) {
		fprintf(fp, "\t\"%s\" -> \"%s\" ", fromname, toname);
		fprintf(fp, "[ dir=both label=\"%d", forward.metric);
		if (forward.metric != reverse.metric)
			fprintf(fp, "/%d", reverse.metric);
		fprintf(fp, "\" ];\n");
	} else {
		fprintf(fp, "\t\"%s\" -> \"%s\" ", fromname, toname);
		fprintf(fp, "[ color=blue dir=none ];\n");
	}
}

static void dump_graph(void *_dummy)
{
	struct iv_avl_node *an;
	FILE *fp;

	fp = fopen("graph.dot.new", "w");
	if (fp == NULL)
		abort();

	fprintf(stderr, "dumping graph\n");

	fprintf(fp, "digraph g {\n");
	fprintf(fp, "\trankdir = RL;\n");

	iv_avl_tree_for_each (an, &loc_rib.ids) {
		struct lsa *from;
		struct iv_avl_node *an2;

		from = iv_container_of(an, struct loc_rib_id, an)->best;
		if (from == NULL)
			continue;

		iv_avl_tree_for_each (an2, &from->root.attrs) {
			struct lsa_attr *peer;

			peer = iv_container_of(an2, struct lsa_attr, an);
			if (peer->type != LSA_ATTR_TYPE_PEER)
				continue;
			if (!peer->data_is_attr_set || !peer->attr_signed)
				continue;
			if (peer->keylen != NODE_ID_LEN)
				continue;

			print_edge(fp, from, lsa_attr_key(peer));
		}
	}

	fprintf(fp, "}\n");

	fclose(fp);

	rename("graph.dot.new", "graph.dot");
}

static void schedule_graph_dump(void)
{
	if (!iv_timer_registered(&dump_timer)) {
		iv_validate_now();
		dump_timer.expires = iv_now;
		timespec_add_ms(&dump_timer.expires, 100, 100);
		iv_timer_register(&dump_timer);
	}
}

static void lsa_add(void *_dummy, struct lsa *a, uint32_t cost)
{
	schedule_graph_dump();
}

static void lsa_mod(void *_dummy, struct lsa *a, uint32_t acost,
		    struct lsa *b, uint32_t bcost)
{
	schedule_graph_dump();
}

static void lsa_del(void *_dummy, struct lsa *a, uint32_t cost)
{
	schedule_graph_dump();
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	loc_rib_listener_unregister(&loc_rib, &rib_listener);
	dgp_connect_stop(&dc);

	iv_signal_unregister(&sigint);
}

int mkgraph(const char *config)
{
	struct conf *conf;
	gnutls_x509_privkey_t privkey;

	conf = parse_config(config);
	if (conf == NULL)
		return 1;

	gnutls_global_init();

	if (x509_read_privkey(&privkey, conf->private_key, 0) < 0)
		return 1;

	free_config(conf);

	x509_get_privkey_id(myid, privkey);

	gnutls_x509_privkey_deinit(privkey);

	gnutls_global_deinit();

	iv_init();

	loc_rib.myid = NULL;
	loc_rib_init(&loc_rib);

	IV_TIMER_INIT(&dump_timer);
	dump_timer.handler = dump_graph;

	rib_listener.lsa_add = lsa_add;
	rib_listener.lsa_mod = lsa_mod;
	rib_listener.lsa_del = lsa_del;
	loc_rib_listener_register(&loc_rib, &rib_listener);

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

	iv_main();

	if (iv_timer_registered(&dump_timer))
		iv_timer_unregister(&dump_timer);

	loc_rib_deinit(&loc_rib);

	iv_deinit();

	return 0;
}
