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

/*
 * TODO:
 * - make SIGHUP handling smarter
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
#include "connect.h"
#include "dvpn.h"
#include "listen.h"
#include "util.h"
#include "x509.h"

#define TYPE_EPEER	0
#define TYPE_CUSTOMER	1
#define TYPE_TRANSIT	2
#define TYPE_IPEER	3

static gnutls_x509_privkey_t key;
static struct iv_avl_tree peers;

static int compare_peers(const void *_a, const void *_b)
{
	const struct peer *a = _a;
	const struct peer *b = _b;

	return memcmp(a->id, b->id, 20);
}

static void connect_set_state(void *_cce, int up)
{
	struct conf_connect_entry *cce = _cce;

	cce->peer.up = up;
}

static void listen_set_state(void *_cle, int up)
{
	struct conf_listen_entry *cle = _cle;

	cle->peer.up = up;
}

static void stop_config(struct conf *conf)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);
		if (!cce->registered)
			continue;

		cce->registered = 0;
		server_peer_unregister(&cce->sp);
		iv_avl_tree_delete(&peers, &cce->peer.an);
	}

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct iv_list_head *lh2;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		if (!cls->registered)
			continue;

		cls->registered = 0;

		iv_list_for_each (lh2, &cls->listen_entries) {
			struct conf_listen_entry *cle;

			cle = iv_list_entry(lh2, struct conf_listen_entry,
					    list);
			listen_entry_unregister(&cle->le);
			iv_avl_tree_delete(&peers, &cle->peer.an);
		}

		listening_socket_unregister(&cls->ls);
	}
}

static int start_config(struct conf *conf)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);

		cce->sp.tunitf = cce->tunitf;
		cce->sp.name = cce->name;
		cce->sp.hostname = cce->hostname;
		cce->sp.port = cce->port;
		cce->sp.key = key;
		memcpy(cce->sp.fingerprint, cce->fingerprint, 20);
		cce->sp.is_peer = cce->is_peer;
		cce->sp.cookie = cce;
		cce->sp.set_state = connect_set_state;
		if (server_peer_register(&cce->sp)) {
			stop_config(conf);
			return 1;
		}

		cce->registered = 1;

		memcpy(cce->peer.id, cce->fingerprint, 20);
		cce->peer.type = cce->is_peer ? TYPE_EPEER : TYPE_TRANSIT;
		cce->peer.up = 0;
		iv_avl_tree_insert(&peers, &cce->peer.an);
	}

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct iv_list_head *lh2;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);

		cls->ls.listen_address = cls->listen_address;
		cls->ls.key = key;
		if (listening_socket_register(&cls->ls)) {
			stop_config(conf);
			return 1;
		}

		cls->registered = 1;

		iv_list_for_each (lh2, &cls->listen_entries) {
			struct conf_listen_entry *cle;

			cle = iv_list_entry(lh2, struct conf_listen_entry,
					    list);

			cle->le.ls = &cls->ls;
			cle->le.tunitf = cle->tunitf;
			cle->le.name = cle->name;
			memcpy(cle->le.fingerprint, cle->fingerprint, 20);
			cle->le.is_peer = cle->is_peer;
			cle->le.cookie = cle;
			cle->le.set_state = listen_set_state;
			listen_entry_register(&cle->le);

			memcpy(cle->peer.id, cle->fingerprint, 20);
			cle->peer.type = cle->is_peer ? TYPE_EPEER :
							TYPE_CUSTOMER;
			cle->peer.up = 0;
			iv_avl_tree_insert(&peers, &cle->peer.an);
		}
	}

	return 0;
}

static const char *config = "/etc/dvpn.ini";
static struct conf *conf;
static struct iv_signal sighup;
static struct iv_signal sigint;

static void got_sighup(void *_dummy)
{
	struct conf *newconf;

	fprintf(stderr, "SIGHUP received, re-reading configuration\n");

	newconf = parse_config(config);
	if (newconf == NULL) {
		fprintf(stderr, "=> error parsing new configuration, "
				"not applying any changes\n");
		return;
	}

	stop_config(conf);

	if (start_config(newconf) == 0) {
		fprintf(stderr, "=> successfully applied new configuration\n");
		free_config(conf);
		conf = newconf;
		return;
	}

	free_config(newconf);
	fprintf(stderr, "=> error applying new configuration, trying to "
			"revert to old configuration\n");

	if (start_config(conf) == 0) {
		fprintf(stderr, "=> successfully reverted to old "
				"configuration\n");
		return;
	}

	fprintf(stderr, "=> error reverting to old configuration, "
			"shutting down\n");

	iv_signal_unregister(&sighup);
	iv_signal_unregister(&sigint);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_signal_unregister(&sighup);
	iv_signal_unregister(&sigint);

	stop_config(conf);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
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

	iv_init();

	INIT_IV_AVL_TREE(&peers, compare_peers);

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

	iv_main();

	iv_deinit();

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	free_config(conf);

	return 0;
}
