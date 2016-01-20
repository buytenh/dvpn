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
#include <getopt.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <string.h>
#include "adj_rib.h"
#include "conf.h"
#include "loc_rib.h"
#include "lsa.h"
#include "lsa_deserialise.h"
#include "lsa_type.h"
#include "rib_listener_debug.h"
#include "rib_listener_to_loc.h"
#include "x509.h"

struct qpeer {
	struct iv_avl_node		an;
	uint8_t				id[32];
	struct iv_fd			query_fd;
	struct sockaddr_in6		query_addr;
	struct iv_timer			query_timer;
	struct iv_timer			query_timeout;
	struct adj_rib			adj_rib_in;
	struct rib_listener_to_loc	to_loc_listener;
};

static void qpeer_find_or_add(uint8_t *id);

static struct iv_avl_tree qpeers;
static struct loc_rib loc_rib;
static struct rib_listener_debug debug_listener;
static struct iv_signal sigint;

static int qpeer_compare(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct qpeer *a = iv_container_of(_a, struct qpeer, an);
	struct qpeer *b = iv_container_of(_b, struct qpeer, an);

	return memcmp(a->id, b->id, 32);
}

static void ping_query_timeout(struct qpeer *qpeer)
{
	if (iv_timer_registered(&qpeer->query_timeout)) {
		iv_timer_unregister(&qpeer->query_timeout);
		iv_validate_now();
		qpeer->query_timeout.expires = iv_now;
		qpeer->query_timeout.expires.tv_sec += 30;
		iv_timer_register(&qpeer->query_timeout);
	}
}

static void got_response(void *_qpeer)
{
	struct qpeer *qpeer = _qpeer;
	uint8_t buf[65536];
	struct sockaddr_storage recvaddr;
	socklen_t addrlen;
	int ret;
	struct lsa *lsa;
	struct iv_avl_node *an;

	addrlen = sizeof(recvaddr);

	ret = recvfrom(qpeer->query_fd.fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&recvaddr, &addrlen);
	if (ret < 0) {
		perror("recvfrom");
		return;
	}

	ping_query_timeout(qpeer);

	lsa = lsa_deserialise(buf, ret);
	if (lsa == NULL) {
		fprintf(stderr, "error deserialising LSA\n");
		adj_rib_flush(&qpeer->adj_rib_in);
		return;
	}

	if (memcmp(qpeer->id, lsa->id, 32)) {
		fprintf(stderr, "node ID mismatch\n");
		lsa_put(lsa);
		return;
	}

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);
		if (attr->type == LSA_ATTR_TYPE_PEER) {
			if (attr->keylen == 32)
				qpeer_find_or_add(lsa_attr_key(attr));
		}
	}

	adj_rib_add_lsa(&qpeer->adj_rib_in, lsa);

	lsa_put(lsa);
}

static void query_timer_expiry(void *_qpeer)
{
	struct qpeer *qpeer = _qpeer;
	uint8_t buf[1];

	qpeer->query_timer.expires.tv_sec++;
	iv_timer_register(&qpeer->query_timer);

	if (sendto(qpeer->query_fd.fd, buf, 0, 0,
		   (struct sockaddr *)&qpeer->query_addr,
		   sizeof(qpeer->query_addr)) < 0) {
		perror("sendto");
		return;
	}
}

static void qpeer_zap(struct qpeer *qpeer)
{
	iv_avl_tree_delete(&qpeers, &qpeer->an);

	iv_fd_unregister(&qpeer->query_fd);
	iv_timer_unregister(&qpeer->query_timer);
	if (iv_timer_registered(&qpeer->query_timeout))
		iv_timer_unregister(&qpeer->query_timeout);
	adj_rib_flush(&qpeer->adj_rib_in);
	rib_listener_to_loc_deinit(&qpeer->to_loc_listener);
	free(qpeer);
}

static void query_timeout_expiry(void *_qpeer)
{
	struct qpeer *qpeer = _qpeer;

	qpeer_zap(qpeer);
}

static void qpeer_add(uint8_t *id, int permanent)
{
	int fd;
	struct qpeer *qpeer;
	uint8_t addr[16];

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return;
	}

	qpeer = malloc(sizeof(*qpeer));
	if (qpeer == NULL) {
		close(fd);
		return;
	}

	memcpy(qpeer->id, id, 32);

	iv_avl_tree_insert(&qpeers, &qpeer->an);

	IV_FD_INIT(&qpeer->query_fd);
	qpeer->query_fd.fd = fd;
	qpeer->query_fd.cookie = qpeer;
	qpeer->query_fd.handler_in = got_response;
	iv_fd_register(&qpeer->query_fd);

	v6_global_addr_from_key_id(addr, id, 32);

	qpeer->query_addr.sin6_family = AF_INET6;
	qpeer->query_addr.sin6_port = htons(19275);
	qpeer->query_addr.sin6_flowinfo = 0;
	memcpy(&qpeer->query_addr.sin6_addr, addr, 16);
	qpeer->query_addr.sin6_scope_id = 0;

	IV_TIMER_INIT(&qpeer->query_timer);
	iv_validate_now();
	qpeer->query_timer.expires = iv_now;
	qpeer->query_timer.cookie = qpeer;
	qpeer->query_timer.handler = query_timer_expiry;
	iv_timer_register(&qpeer->query_timer);

	IV_TIMER_INIT(&qpeer->query_timeout);
	if (!permanent) {
		iv_validate_now();
		qpeer->query_timeout.expires = iv_now;
		qpeer->query_timeout.expires.tv_sec += 30;
		qpeer->query_timeout.cookie = qpeer;
		qpeer->query_timeout.handler = query_timeout_expiry;
		iv_timer_register(&qpeer->query_timeout);
	}

	memset(&qpeer->adj_rib_in.myid, 0, 32);
	memcpy(&qpeer->adj_rib_in.remoteid, id, 32);
	adj_rib_init(&qpeer->adj_rib_in);

	qpeer->to_loc_listener.dest = &loc_rib;
	rib_listener_to_loc_init(&qpeer->to_loc_listener);

	adj_rib_listener_register(&qpeer->adj_rib_in,
				  &qpeer->to_loc_listener.rl);
}

static struct qpeer *qpeer_find(uint8_t *id)
{
	struct iv_avl_node *an;

	an = qpeers.root;
	while (an != NULL) {
		struct qpeer *qpeer;
		int ret;

		qpeer = iv_container_of(an, struct qpeer, an);

		ret = memcmp(id, qpeer->id, 32);
		if (ret == 0)
			return qpeer;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static void qpeer_find_or_add(uint8_t *id)
{
	struct qpeer *qpeer;

	qpeer = qpeer_find(id);
	if (qpeer != NULL) {
		ping_query_timeout(qpeer);
		return;
	}

	qpeer_add(id, 0);
}

static void qpeer_add_config(const char *config)
{
	struct conf *conf;
	gnutls_x509_privkey_t key;
	uint8_t id[32];

	conf = parse_config(config);
	if (conf == NULL)
		return;

	if (x509_read_privkey(&key, conf->private_key) < 0)
		return;

	free_config(conf);

	x509_get_key_id(id, key);

	gnutls_x509_privkey_deinit(key);

	qpeer_add(id, 1);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	while (!iv_avl_tree_empty(&qpeers)) {
		struct iv_avl_node *an;

		an = iv_avl_tree_min(&qpeers);
		qpeer_zap(iv_container_of(an, struct qpeer, an));
	}

	iv_signal_unregister(&sigint);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
		{ 0, 0, 0, 0, },
	};
	const char *config = "/etc/dvpn.ini";

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

	iv_init();

	INIT_IV_AVL_TREE(&qpeers, qpeer_compare);

	loc_rib_init(&loc_rib);

	debug_listener.name = "loc-rib";
	rib_listener_debug_init(&debug_listener);

	loc_rib_listener_register(&loc_rib, &debug_listener.rl);

	gnutls_global_init();
	qpeer_add_config(config);
	gnutls_global_deinit();

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	loc_rib_deinit(&loc_rib);

	rib_listener_debug_deinit(&debug_listener);

	iv_deinit();

	return 0;
}
