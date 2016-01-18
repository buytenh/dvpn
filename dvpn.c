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
#include <iv_avl.h>
#include <iv_signal.h>
#include <string.h>
#include "conf.h"
#include "confdiff.h"
#include "connect.h"
#include "dvpn.h"
#include "listen.h"
#include "lsa.h"
#include "lsa_path.h"
#include "lsa_print.h"
#include "lsa_serialise.h"
#include "lsa_type.h"
#include "util.h"
#include "x509.h"

static gnutls_x509_privkey_t key;
static uint8_t keyid[32];
static struct iv_avl_tree peers;
static struct lsa *me;
static struct iv_fd topo_fd;

static int compare_peers(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct peer *a = iv_container_of(_a, struct peer, an);
	struct peer *b = iv_container_of(_b, struct peer, an);

	return memcmp(a->id, b->id, 32);
}

static void got_topo_request(void *_dummy)
{
	uint8_t buf[65536];
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	int ret;
	struct lsa *newlsa;
	int len;

	addrlen = sizeof(addr);
	ret = recvfrom(topo_fd.fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &addrlen);
	if (ret < 0) {
		if (errno != EAGAIN)
			perror("got_topo_request: recvfrom");
		return;
	}

	newlsa = lsa_clone(me);
	if (newlsa == NULL)
		abort();

	lsa_path_prepend(newlsa, keyid);

	len = lsa_serialise(buf, sizeof(buf), newlsa);
	if (len > sizeof(buf))
		abort();

	lsa_put(newlsa);

	sendto(topo_fd.fd, buf, len, 0, (struct sockaddr *)&addr, addrlen);
}

static int start_topo_listener(void)
{
	int fd;
	int yes;
	uint8_t a[16];
	struct sockaddr_in6 addr;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("start_topo_listener: socket");
		return 1;
	}

	yes = 1;
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &yes, sizeof(yes)) < 0) {
		perror("start_topo_listener: setsockopt(SOL_IP, IP_FREEBIND)");
		close(fd);
		return 1;
	}

	v6_global_addr_from_key_id(a, keyid, sizeof(keyid));

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(19275);
	addr.sin6_flowinfo = 0;
	memcpy(&addr.sin6_addr, a, 16);
	addr.sin6_scope_id = 0;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("start_topo_listener: bind");
		close(fd);
		return 1;
	}

	IV_FD_INIT(&topo_fd);
	topo_fd.fd = fd;
	topo_fd.handler_in = got_topo_request;
	iv_fd_register(&topo_fd);

	return 0;
}

static enum lsa_peer_type peer_type_to_lsa_peer_type(enum peer_type type)
{
	switch (type) {
	case PEER_TYPE_EPEER:
		return LSA_PEER_TYPE_EPEER;
	case PEER_TYPE_CUSTOMER:
		return LSA_PEER_TYPE_CUSTOMER;
	case PEER_TYPE_TRANSIT:
		return LSA_PEER_TYPE_TRANSIT;
	case PEER_TYPE_IPEER:
		return LSA_PEER_TYPE_IPEER;
	default:
		fprintf(stderr, "peer_type_to_lsa_peer_type: invalid "
				"type %d\n", type);
		return LSA_PEER_TYPE_EPEER;
	}
}

static void connect_set_state(void *_cce, int up)
{
	struct conf_connect_entry *cce = _cce;

	cce->peer.up = up;

	if (up) {
		struct lsa_attr_peer data;

		data.metric = htons(1);
		data.peer_type = peer_type_to_lsa_peer_type(cce->peer_type);

		lsa_attr_add(me, LSA_ATTR_TYPE_PEER, cce->fingerprint,
			     sizeof(cce->fingerprint), &data, sizeof(data));
	} else {
		lsa_attr_del_key(me, LSA_ATTR_TYPE_PEER,
				 cce->fingerprint, sizeof(cce->fingerprint));
	}
}

static void listen_set_state(void *_cle, int up)
{
	struct conf_listen_entry *cle = _cle;

	cle->peer.up = up;

	if (up) {
		struct lsa_attr_peer data;

		data.metric = htons(1);
		data.peer_type = peer_type_to_lsa_peer_type(cle->peer_type);

		lsa_attr_add(me, LSA_ATTR_TYPE_PEER, cle->fingerprint,
			     sizeof(cle->fingerprint), &data, sizeof(data));
	} else {
		lsa_attr_del_key(me, LSA_ATTR_TYPE_PEER,
				 cle->fingerprint, sizeof(cle->fingerprint));
	}
}

static int start_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->sp.tunitf = cce->tunitf;
	cce->sp.name = cce->name;
	cce->sp.hostname = cce->hostname;
	cce->sp.port = cce->port;
	cce->sp.key = key;
	memcpy(cce->sp.fingerprint, cce->fingerprint, 32);
	cce->sp.peer_type = cce->peer_type;
	cce->sp.cookie = cce;
	cce->sp.set_state = connect_set_state;
	if (server_peer_register(&cce->sp))
		return 1;

	cce->registered = 1;

	memcpy(cce->peer.id, cce->fingerprint, 32);
	cce->peer.peer_type = cce->peer_type;
	cce->peer.up = 0;
	iv_avl_tree_insert(&peers, &cce->peer.an);

	return 0;
}

static void stop_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->registered = 0;
	server_peer_unregister(&cce->sp);
	iv_avl_tree_delete(&peers, &cce->peer.an);

	if (cce->peer.up) {
		lsa_attr_del_key(me, LSA_ATTR_TYPE_PEER,
				 cce->fingerprint, sizeof(cce->fingerprint));
	}
}

static int start_conf_listen_entry(struct conf_listening_socket *cls,
				   struct conf_listen_entry *cle)
{
	cle->le.ls = &cls->ls;
	cle->le.tunitf = cle->tunitf;
	cle->le.name = cle->name;
	memcpy(cle->le.fingerprint, cle->fingerprint, 32);
	cle->le.peer_type = cle->peer_type;
	cle->le.cookie = cle;
	cle->le.set_state = listen_set_state;
	if (listen_entry_register(&cle->le))
		return 1;

	cle->registered = 1;

	memcpy(cle->peer.id, cle->fingerprint, 32);
	cle->peer.peer_type = cle->peer_type;
	cle->peer.up = 0;
	iv_avl_tree_insert(&peers, &cle->peer.an);

	return 0;
}

static void stop_conf_listen_entry(struct conf_listen_entry *cle)
{
	cle->registered = 0;
	listen_entry_unregister(&cle->le);
	iv_avl_tree_delete(&peers, &cle->peer.an);

	if (cle->peer.up) {
		lsa_attr_del_key(me, LSA_ATTR_TYPE_PEER,
				 cle->fingerprint, sizeof(cle->fingerprint));
	}
}

static int start_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_list_head *lh;

	cls->ls.listen_address = cls->listen_address;
	cls->ls.key = key;
	if (listening_socket_register(&cls->ls))
		return 1;

	cls->registered = 1;

	iv_list_for_each (lh, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (start_conf_listen_entry(cls, cle))
			return 1;
	}

	return 0;
}

static void stop_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_list_head *lh;

	cls->registered = 0;

	iv_list_for_each (lh, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (cle->registered)
			stop_conf_listen_entry(cle);
	}

	listening_socket_unregister(&cls->ls);
}

static void stop_config(struct conf *conf)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);
		if (cce->registered)
			stop_conf_connect_entry(cce);
	}

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		if (cls->registered)
			stop_conf_listening_socket(cls);
	}
}

static int start_config(struct conf *conf)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);
		if (start_conf_connect_entry(cce))
			goto err;
	}

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		if (start_conf_listening_socket(cls))
			goto err;
	}

	return 0;

err:
	stop_config(conf);

	return 1;
}

static const char *config = "/etc/dvpn.ini";
static struct conf *conf;
static struct iv_signal sighup;
static struct iv_signal sigint;
static struct iv_signal sigusr1;

static int new_connect_entry(struct conf_connect_entry *cce)
{
	return start_conf_connect_entry(cce);
}

static void removed_connect_entry(struct conf_connect_entry *cce)
{
	stop_conf_connect_entry(cce);
}

static int new_listening_socket(struct conf_listening_socket *cls)
{
	return start_conf_listening_socket(cls);
}

static void removed_listening_socket(struct conf_listening_socket *cls)
{
	stop_conf_listening_socket(cls);
}

static int new_listen_entry(struct conf_listening_socket *cls,
			    struct conf_listen_entry *cle)
{
	return start_conf_listen_entry(cls, cle);
}

static void removed_listen_entry(struct conf_listening_socket *cls,
				 struct conf_listen_entry *cle)
{
	stop_conf_listen_entry(cle);
}

static void got_sighup(void *_dummy)
{
	struct conf *newconf;
	struct confdiff_request req;

	fprintf(stderr, "SIGHUP received, re-reading configuration\n");

	newconf = parse_config(config);
	if (newconf == NULL) {
		fprintf(stderr, "error parsing new configuration\n");
		return;
	}

	req.conf = conf;
	req.newconf = newconf;
	req.new_connect_entry = new_connect_entry;
	req.removed_connect_entry = removed_connect_entry;
	req.new_listening_socket = new_listening_socket;
	req.removed_listening_socket = removed_listening_socket;
	req.new_listen_entry = new_listen_entry;
	req.removed_listen_entry = removed_listen_entry;
	diff_configs(&req);

	free_config(newconf);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_fd_unregister(&topo_fd);
	iv_signal_unregister(&sighup);
	iv_signal_unregister(&sigint);
	iv_signal_unregister(&sigusr1);

	stop_config(conf);
}

static void got_sigusr1(void *_dummy)
{
	struct iv_avl_node *an;

	fprintf(stderr, "=== configured peers =================="
			"=======================================\n");

	iv_avl_tree_for_each (an, &peers) {
		struct peer *p;

		p = iv_container_of(an, struct peer, an);

		printhex(stderr, p->id, 32);
		fprintf(stderr, " - ");
		fprintf(stderr, "%s\n", p->up ? "up" : "down");
	}

	fprintf(stderr, "\n");

	lsa_print(stderr, me);

	fprintf(stderr, "======================================="
			"=======================================\n");
}

static void usage(const char *me)
{
	fprintf(stderr, "syntax: %s [-c <config.ini>]\n", me);
	fprintf(stderr, "        %s [--show-key-id <key.pem>]\n", me);
}

static int show_key_id(const char *file)
{
	gnutls_x509_privkey_t key;
	int ret;

	gnutls_global_init();

	ret = x509_read_privkey(&key, file);
	if (ret == 0) {
		ret = x509_get_key_id(keyid, sizeof(keyid), key);
		if (ret >= 0) {
			printhex(stdout, keyid, ret);
			printf("\n");
		}
		gnutls_x509_privkey_deinit(key);
	}

	gnutls_global_deinit();

	return !!ret;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
		{ "show-key-id", required_argument, 0, 'k' },
		{ 0, 0, 0, 0, },
	};

	while (1) {
		int c;

		c = getopt_long(argc, argv, "c:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config = optarg;
			break;

		case 'k':
			return show_key_id(optarg);

		case '?':
			usage(argv[0]);
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

	if (x509_get_key_id(keyid, sizeof(keyid), key) < 0)
		return 1;

	fprintf(stderr, "dvpn: using key ID ");
	printhex(stderr, keyid, sizeof(keyid));
	fprintf(stderr, "\n");

	iv_init();

	me = lsa_alloc(keyid);
	lsa_attr_add(me, LSA_ATTR_TYPE_ADV_PATH, NULL, 0, NULL, 0);

	INIT_IV_AVL_TREE(&peers, compare_peers);

	if (start_topo_listener())
		return 1;

	if (start_config(conf))
		return 1;

	IV_SIGNAL_INIT(&sighup);
	sighup.signum = SIGHUP;
	sighup.flags = 0;
	sighup.cookie = NULL;
	sighup.handler = got_sighup;
	iv_signal_register(&sighup);

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

	iv_deinit();

	close(topo_fd.fd);

	lsa_put(me);

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	free_config(conf);

	return 0;
}
