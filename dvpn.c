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
#include <iv_signal.h>
#include <net/if.h>
#include <string.h>
#include "conf.h"
#include "confdiff.h"
#include "lsa.h"
#include "lsa_path.h"
#include "lsa_print.h"
#include "lsa_serialise.h"
#include "lsa_type.h"
#include "tconn_connect.h"
#include "tconn_listen.h"
#include "util.h"
#include "x509.h"

static gnutls_x509_privkey_t key;
static uint8_t keyid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct dgp_listen_socket dls;
static struct lsa *me;

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

static void local_add_peer(uint8_t *id, enum peer_type type)
{
	struct lsa *newme;
	struct lsa_attr_peer data;

	newme = lsa_clone(me);

	data.metric = htons(1);
	data.peer_type = peer_type_to_lsa_peer_type(type);
	lsa_attr_add(newme, LSA_ATTR_TYPE_PEER, id, NODE_ID_LEN,
		     &data, sizeof(data));

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

static void local_del_peer(uint8_t *id)
{
	struct lsa *newme;

	newme = lsa_clone(me);

	lsa_attr_del_key(newme, LSA_ATTR_TYPE_PEER, id, NODE_ID_LEN);

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

static void connect_set_state(void *_cce, int up)
{
	struct conf_connect_entry *cce = _cce;

	cce->tconn_up = up;

	if (up) {
		local_add_peer(cce->fingerprint, cce->peer_type);
		dgp_connect_start(&cce->dc);
	} else {
		dgp_connect_stop(&cce->dc);
		local_del_peer(cce->fingerprint);
	}
}

static void listen_set_state(void *_cle, int up)
{
	struct conf_listen_entry *cle = _cle;

	cle->tconn_up = up;

	if (up) {
		local_add_peer(cle->fingerprint, cle->peer_type);
	} else {
		dgp_listen_entry_reset(&cle->dle);
		local_del_peer(cle->fingerprint);
	}
}

static int start_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->tc.tunitf = cce->tunitf;
	cce->tc.name = cce->name;
	cce->tc.hostname = cce->hostname;
	cce->tc.port = cce->port;
	cce->tc.key = key;
	cce->tc.fingerprint = cce->fingerprint;
	cce->tc.peer_type = cce->peer_type;
	cce->tc.cookie = cce;
	cce->tc.set_state = connect_set_state;
	if (tconn_connect_start(&cce->tc))
		return 1;

	cce->registered = 1;

	cce->dc.myid = keyid;
	cce->dc.remoteid = cce->fingerprint;
	cce->dc.ifindex = if_nametoindex(tun_interface_get_name(&cce->tc.tun));
	cce->dc.loc_rib = &loc_rib;

	return 0;
}

static void stop_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->registered = 0;

	if (cce->tconn_up) {
		dgp_connect_stop(&cce->dc);
		local_del_peer(cce->fingerprint);
	}

	tconn_connect_destroy(&cce->tc);
}

static int start_conf_listen_entry(struct conf_listening_socket *cls,
				   struct conf_listen_entry *cle)
{
	cle->tle.tls = &cls->tls;
	cle->tle.tunitf = cle->tunitf;
	cle->tle.name = cle->name;
	cle->tle.fingerprint = cle->fingerprint;
	cle->tle.peer_type = cle->peer_type;
	cle->tle.cookie = cle;
	cle->tle.set_state = listen_set_state;
	if (tconn_listen_entry_register(&cle->tle))
		return 1;

	cle->registered = 1;

	cle->dls.myid = keyid;
	cle->dls.ifindex = if_nametoindex(tun_interface_get_name(&cle->tle.tun));
	cle->dls.loc_rib = &loc_rib;
	cle->dls.permit_readonly = 0;
	dgp_listen_socket_register(&cle->dls);

	cle->dle.dls = &cle->dls;
	cle->dle.remoteid = cle->fingerprint;
	dgp_listen_entry_register(&cle->dle);

	return 0;
}

static void stop_conf_listen_entry(struct conf_listen_entry *cle)
{
	cle->registered = 0;
	tconn_listen_entry_unregister(&cle->tle);
	dgp_listen_socket_unregister(&cle->dls);
	dgp_listen_entry_unregister(&cle->dle);

	if (cle->tconn_up)
		local_del_peer(cle->fingerprint);
}

static int start_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_list_head *lh;

	cls->tls.listen_address = cls->listen_address;
	cls->tls.key = key;
	if (tconn_listen_socket_register(&cls->tls))
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

	tconn_listen_socket_unregister(&cls->tls);
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

	iv_signal_unregister(&sighup);
	iv_signal_unregister(&sigint);
	iv_signal_unregister(&sigusr1);

	stop_config(conf);

	dgp_listen_socket_unregister(&dls);
}

static void got_sigusr1(void *_dummy)
{
	lsa_print(stderr, me, &loc_rib);
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
		ret = x509_get_key_id(keyid, key);
		if (ret == 0) {
			printhex(stdout, keyid, NODE_ID_LEN);
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

	if (x509_get_key_id(keyid, key) < 0)
		return 1;

	fprintf(stderr, "dvpn: using key ID ");
	printhex(stderr, keyid, NODE_ID_LEN);
	fprintf(stderr, "\n");

	iv_init();

	loc_rib_init(&loc_rib);

	dls.myid = keyid;
	dls.ifindex = 0;
	dls.loc_rib = &loc_rib;
	dls.permit_readonly = 1;
	dgp_listen_socket_register(&dls);

	me = lsa_alloc(keyid);
	lsa_attr_add(me, LSA_ATTR_TYPE_ADV_PATH, NULL, 0, NULL, 0);
	if (conf->node_name != NULL) {
		lsa_attr_add(me, LSA_ATTR_TYPE_NODE_NAME, NULL, 0,
			     conf->node_name, strlen(conf->node_name));
	}
	loc_rib_add_lsa(&loc_rib, me);

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

	loc_rib_del_lsa(&loc_rib, me);
	lsa_put(me);

	loc_rib_deinit(&loc_rib);

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	free_config(conf);

	return 0;
}
