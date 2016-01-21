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

static uint8_t local_id[32];

static struct loc_rib loc_rib;
static struct rib_listener_debug loc_rib_debug_listener;

static struct iv_fd local_query_fd;
static struct sockaddr_in6 local_query_addr;
static struct iv_timer local_query_timer;
static struct adj_rib local_adj_rib_in;
static struct rib_listener_to_loc local_to_loc_listener;

static struct iv_fd fd_incoming;

static struct iv_signal sigint;

static void read_local_id(const char *config)
{
	struct conf *conf;
	gnutls_x509_privkey_t key;

	conf = parse_config(config);
	if (conf == NULL)
		abort();

	if (x509_read_privkey(&key, conf->private_key) < 0)
		abort();

	free_config(conf);

	x509_get_key_id(local_id, key);

	gnutls_x509_privkey_deinit(key);
}

static void got_response(void *_dummy)
{
	uint8_t buf[65536];
	struct sockaddr_storage recvaddr;
	socklen_t addrlen;
	int ret;
	struct lsa *lsa;

	addrlen = sizeof(recvaddr);

	ret = recvfrom(local_query_fd.fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&recvaddr, &addrlen);
	if (ret < 0) {
		perror("recvfrom");
		return;
	}

	lsa = lsa_deserialise(buf, ret);
	if (lsa == NULL) {
		fprintf(stderr, "error deserialising LSA\n");
		adj_rib_flush(&local_adj_rib_in);
		return;
	}

	if (memcmp(lsa->id, local_id, 32)) {
		fprintf(stderr, "node ID mismatch\n");
		lsa_put(lsa);
		return;
	}

	adj_rib_add_lsa(&local_adj_rib_in, lsa);

	lsa_put(lsa);
}

static void query_timer_expiry(void *_dummy)
{
	uint8_t buf[1];

	local_query_timer.expires.tv_nsec += 100000000;
	if (local_query_timer.expires.tv_nsec >= 1000000000) {
		local_query_timer.expires.tv_sec++;
		local_query_timer.expires.tv_nsec -= 1000000000;
	}
	iv_timer_register(&local_query_timer);

	if (sendto(local_query_fd.fd, buf, 0, 0,
		   (struct sockaddr *)&local_query_addr,
		   sizeof(local_query_addr)) < 0) {
		perror("sendto");
		return;
	}
}

static void query_start(void)
{
	int fd;
	uint8_t addr[16];

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	IV_FD_INIT(&local_query_fd);
	local_query_fd.fd = fd;
	local_query_fd.handler_in = got_response;
	iv_fd_register(&local_query_fd);

	v6_global_addr_from_key_id(addr, local_id, 32);

	local_query_addr.sin6_family = AF_INET6;
	local_query_addr.sin6_port = htons(19275);
	local_query_addr.sin6_flowinfo = 0;
	memcpy(&local_query_addr.sin6_addr, addr, 16);
	local_query_addr.sin6_scope_id = 0;

	IV_TIMER_INIT(&local_query_timer);
	iv_validate_now();
	local_query_timer.expires = iv_now;
	local_query_timer.handler = query_timer_expiry;
	iv_timer_register(&local_query_timer);

	memset(&local_adj_rib_in.myid, 0, 32);
	memcpy(&local_adj_rib_in.remoteid, local_id, 32);
	adj_rib_init(&local_adj_rib_in);

	local_to_loc_listener.dest = &loc_rib;
	rib_listener_to_loc_init(&local_to_loc_listener);
	adj_rib_listener_register(&local_adj_rib_in, &local_to_loc_listener.rl);
}

static void got_connection(void *_dummy)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd;

	addrlen = sizeof(addr);

	fd = accept(fd_incoming.fd, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		perror("got_connection: accept");
		return;
	}

	close(fd);
}

static void listen_start(void)
{
	int fd;
	int yes;
	uint8_t addr[16];
	struct sockaddr_in6 saddr;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("listen_start: setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		exit(1);
	}
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &yes, sizeof(yes)) < 0) {
		perror("listen_start: setsockopt(SOL_IP, IP_FREEBIND)");
		exit(1);
	}

	v6_global_addr_from_key_id(addr, local_id, 32);

	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(44461);
	saddr.sin6_flowinfo = 0;
	memcpy(&saddr.sin6_addr, addr, 16);
	saddr.sin6_scope_id = 0;

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("listen_start: bind");
		exit(1);
	}

	if (listen(fd, 100) < 0) {
		perror("listen_start: listen");
		exit(1);
	}

	IV_FD_INIT(&fd_incoming);
	fd_incoming.fd = fd;
	fd_incoming.handler_in = got_connection;
	iv_fd_register(&fd_incoming);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_fd_unregister(&local_query_fd);
	iv_timer_unregister(&local_query_timer);
	adj_rib_flush(&local_adj_rib_in);
	rib_listener_to_loc_deinit(&local_to_loc_listener);

	iv_fd_unregister(&fd_incoming);
	close(fd_incoming.fd);

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

	gnutls_global_init();
	read_local_id(config);
	gnutls_global_deinit();

	loc_rib_init(&loc_rib);

	loc_rib_debug_listener.name = "loc-rib";
	rib_listener_debug_init(&loc_rib_debug_listener);
	loc_rib_listener_register(&loc_rib, &loc_rib_debug_listener.rl);

	query_start();

	listen_start();

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	loc_rib_deinit(&loc_rib);

	rib_listener_debug_deinit(&loc_rib_debug_listener);

	iv_deinit();

	return 0;
}
