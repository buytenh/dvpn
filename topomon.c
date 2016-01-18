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
#include "lsa.h"
#include "lsa_deserialise.h"
#include "x509.h"

static uint8_t nodeid[32];
static struct iv_fd topo_query_fd;
static struct sockaddr_in6 topo_query_addr;
static struct iv_timer topo_query_timer;
static struct adj_rib *rib_in;
static struct rib_listener *debug_listener;

static void got_response(void *_dummy)
{
	uint8_t buf[65536];
	struct sockaddr_storage recvaddr;
	socklen_t addrlen;
	int ret;
	struct lsa *newlsa;

	addrlen = sizeof(recvaddr);

	ret = recvfrom(topo_query_fd.fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&recvaddr, &addrlen);
	if (ret < 0) {
		perror("recvfrom");
		return;
	}

	newlsa = lsa_deserialise(buf, ret);
	if (newlsa == NULL) {
		fprintf(stderr, "error deserialising LSA\n");
		adj_rib_flush(rib_in);
		return;
	}

	if (memcmp(nodeid, newlsa->id, 32)) {
		fprintf(stderr, "node ID mismatch\n");
		lsa_put(newlsa);
		return;
	}

	adj_rib_add_lsa(rib_in, newlsa);

	lsa_put(newlsa);
}

static void topo_query_timer_expiry(void *_dummy)
{
	uint8_t buf[1];

	topo_query_timer.expires.tv_nsec += 100000000;
	if (topo_query_timer.expires.tv_nsec >= 1000000000) {
		topo_query_timer.expires.tv_sec++;
		topo_query_timer.expires.tv_nsec -= 1000000000;
	}
	iv_timer_register(&topo_query_timer);

	if (sendto(topo_query_fd.fd, buf, 0, 0,
		   (struct sockaddr *)&topo_query_addr,
		   sizeof(topo_query_addr)) < 0) {
		perror("sendto");
		return;
	}
}

static struct iv_signal sigint;

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_fd_unregister(&topo_query_fd);
	iv_timer_unregister(&topo_query_timer);
	iv_signal_unregister(&sigint);
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
	int fd;
	uint8_t nodeaddr[16];
	uint8_t zeroid[32];

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

	x509_get_key_id(nodeid, sizeof(nodeid), key);

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	free_config(conf);

	iv_init();

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	IV_FD_INIT(&topo_query_fd);
	topo_query_fd.fd = fd;
	topo_query_fd.handler_in = got_response;
	iv_fd_register(&topo_query_fd);

	v6_global_addr_from_key_id(nodeaddr, nodeid, sizeof(nodeid));

	topo_query_addr.sin6_family = AF_INET6;
	topo_query_addr.sin6_port = htons(19275);
	topo_query_addr.sin6_flowinfo = 0;
	memcpy(&topo_query_addr.sin6_addr, nodeaddr, 16);
	topo_query_addr.sin6_scope_id = 0;

	IV_TIMER_INIT(&topo_query_timer);
	iv_validate_now();
	topo_query_timer.expires = iv_now;
	topo_query_timer.handler = topo_query_timer_expiry;
	iv_timer_register(&topo_query_timer);

	memset(zeroid, 0, 32);

	rib_in = adj_rib_alloc(zeroid, nodeid);

	debug_listener = debug_listener_new("topomon");
	adj_rib_listener_register(rib_in, debug_listener);

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	iv_deinit();

	adj_rib_listener_unregister(rib_in, debug_listener);
	debug_listener_free(debug_listener);

	adj_rib_free(rib_in);

	return 0;
}
