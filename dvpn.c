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
#include "itf.h"
#include "loc_rib_print.h"
#include "lsa.h"
#include "lsa_path.h"
#include "lsa_serialise.h"
#include "lsa_type.h"
#include "rt_builder.h"
#include "tconn_connect.h"
#include "tconn_listen.h"
#include "tun.h"
#include "util.h"
#include "x509.h"

static gnutls_x509_privkey_t privkey;
static uint8_t keyid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct rt_builder rb;
static struct dgp_listen_socket dls;
static struct lsa *me;

static void rt_add(void *_dummy, uint8_t *dest, uint8_t *nh)
{
	if (nh != NULL)
		itf_add_route_v6_via(dest, nh);
}

static void rt_mod(void *_dummy, uint8_t *dest, uint8_t *oldnh, uint8_t *newnh)
{
	if (newnh != NULL)
		itf_chg_route_v6_via(dest, newnh);
}

static void rt_del(void *_dummy, uint8_t *dest, uint8_t *nh)
{
	if (nh != NULL)
		itf_del_route_v6_via(dest, nh);
}

static enum lsa_peer_type
conf_peer_type_to_lsa_peer_type(enum conf_peer_type type)
{
	switch (type) {
	case CONF_PEER_TYPE_EPEER:
		return LSA_PEER_TYPE_EPEER;
	case CONF_PEER_TYPE_CUSTOMER:
		return LSA_PEER_TYPE_CUSTOMER;
	case CONF_PEER_TYPE_TRANSIT:
		return LSA_PEER_TYPE_TRANSIT;
	case CONF_PEER_TYPE_IPEER:
		return LSA_PEER_TYPE_IPEER;
	default:
		fprintf(stderr, "conf_peer_type_to_lsa_peer_type: invalid "
				"type %d\n", type);
		abort();
	}
}

static void lsa_add_version(struct lsa *lsa, uint64_t version)
{
	uint32_t t32[2];

	t32[0] = htonl((version >> 32) & 0xffffffff);
	t32[1] = htonl(version & 0xffffffff);
	lsa_add_attr(lsa, LSA_ATTR_TYPE_VERSION, NULL, 0, t32, sizeof(t32));
}

static void lsa_update_version(struct lsa *lsa)
{
	struct lsa_attr *attr;
	uint32_t *data;
	uint64_t curver;
	uint64_t t64;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_VERSION, NULL, 0);
	if (attr == NULL)
		abort();

	data = lsa_attr_data(attr);

	curver = ntohl(data[0]);
	curver <<= 32;
	curver |= ntohl(data[1]);

	lsa_del_attr(lsa, attr);

	t64 = time(NULL);
	t64 <<= 8;
	if (t64 <= curver)
		t64 = curver + 1;

	lsa_add_version(lsa, t64);
}

static void lsa_initial_version(struct lsa *lsa)
{
	uint64_t t64;

	t64 = time(NULL);
	lsa_add_version(lsa, (t64 + 1) << 8);
}

static void
lsa_add_pubkey_from_privkey(struct lsa *lsa, gnutls_x509_privkey_t privkey)
{
	uint8_t buf[65536];
	int len;

	len = x509_privkey_to_der_pubkey(buf, sizeof(buf), privkey);
	if (len < 0)
		abort();

	lsa_add_attr(lsa, LSA_ATTR_TYPE_PUBKEY, NULL, 0, buf, len);
}

static void local_add_peer(uint8_t *id, enum conf_peer_type type, int cost)
{
	struct lsa *newme;
	struct lsa_attr_set *set;
	uint16_t metric;
	uint8_t peer_type;

	newme = lsa_clone(me);

	set = lsa_add_attr_set(newme, LSA_ATTR_TYPE_PEER, id, NODE_ID_LEN);

	metric = htons(cost);
	lsa_attr_set_add_attr(newme, set, LSA_PEER_ATTR_TYPE_METRIC,
			      NULL, 0, &metric, sizeof(metric));

	peer_type = conf_peer_type_to_lsa_peer_type(type);
	lsa_attr_set_add_attr(newme, set, LSA_PEER_ATTR_TYPE_PEER_TYPE,
			      NULL, 0, &peer_type, sizeof(peer_type));

	lsa_update_version(newme);

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

static void local_del_peer(uint8_t *id)
{
	struct lsa *newme;

	newme = lsa_clone(me);

	lsa_del_attr_bykey(newme, LSA_ATTR_TYPE_PEER, id, NODE_ID_LEN);

	lsa_update_version(newme);

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

static void cce_tun_got_packet(void *_cce, uint8_t *buf, int len)
{
	struct conf_connect_entry *cce = _cce;
	uint8_t sndbuf[len + 3];

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	tconn_connect_record_send(&cce->tc, sndbuf, len + 3);
}

static void cce_set_state(void *_cce, int up)
{
	struct conf_connect_entry *cce = _cce;
	char *tunitf;

	tunitf = tun_interface_get_name(&cce->tun);

	cce->tconn_up = up;

	if (up) {
		int maxseg;
		int mtu;
		uint8_t addr[16];

		if (cce->peer_type != CONF_PEER_TYPE_DBONLY) {
			local_add_peer(cce->fingerprint, cce->peer_type,
				       cce->cost);
		}

		maxseg = tconn_connect_get_maxseg(&cce->tc);
		if (maxseg < 0)
			abort();

		mtu = maxseg - 5 - 8 - 3 - 16;
		if (mtu < 1280)
			mtu = 1280;
		else if (mtu > 1500)
			mtu = 1500;

		fprintf(stderr, "%s: setting interface MTU to %d\n",
			cce->name, mtu);
		itf_set_mtu(tunitf, mtu);

		itf_set_state(tunitf, 1);

		v6_linklocal_addr_from_key_id(addr, keyid);
		itf_add_addr_v6(tunitf, addr, 10);

		v6_global_addr_from_key_id(addr, keyid);
		itf_add_addr_v6(tunitf, addr, 128);

		v6_global_addr_from_key_id(addr, cce->fingerprint);
		itf_add_route_v6_direct(tunitf, addr);

		dgp_connect_start(&cce->dc);
	} else {
		dgp_connect_stop(&cce->dc);

		itf_set_state(tunitf, 0);

		if (cce->peer_type != CONF_PEER_TYPE_DBONLY)
			local_del_peer(cce->fingerprint);
	}
}

static void cce_record_received(void *_cce, const uint8_t *rec, int len)
{
	struct conf_connect_entry *cce = _cce;
	int rlen;

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	tun_interface_send_packet(&cce->tun, rec + 3, rlen);
}

static void cle_tun_got_packet(void *_cle, uint8_t *buf, int len)
{
	struct conf_listen_entry *cle = _cle;
	uint8_t sndbuf[len + 3];

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	tconn_listen_entry_record_send(&cle->tle, sndbuf, len + 3);
}

static void cle_set_state(void *_cle, int up)
{
	struct conf_listen_entry *cle = _cle;
	char *tunitf;

	tunitf = tun_interface_get_name(&cle->tun);

	cle->tconn_up = up;

	if (up) {
		int maxseg;
		int mtu;
		uint8_t addr[16];

		if (cle->peer_type != CONF_PEER_TYPE_DBONLY) {
			local_add_peer(cle->fingerprint, cle->peer_type,
				       cle->cost);
		}

		maxseg = tconn_listen_entry_get_maxseg(&cle->tle);
		if (maxseg < 0)
			abort();

		mtu = maxseg - 5 - 8 - 3 - 16;
		if (mtu < 1280)
			mtu = 1280;
		else if (mtu > 1500)
			mtu = 1500;

		fprintf(stderr, "%s: setting interface MTU to %d\n",
			cle->name, mtu);
		itf_set_mtu(tunitf, mtu);

		itf_set_state(tunitf, 1);

		v6_linklocal_addr_from_key_id(addr, keyid);
		itf_add_addr_v6(tunitf, addr, 10);

		v6_global_addr_from_key_id(addr, keyid);
		itf_add_addr_v6(tunitf, addr, 128);

		v6_global_addr_from_key_id(addr, cle->fingerprint);
		itf_add_route_v6_direct(tunitf, addr);

		dgp_listen_socket_register(&cle->dls);
		dgp_listen_entry_register(&cle->dle);
	} else {
		dgp_listen_entry_unregister(&cle->dle);
		dgp_listen_socket_unregister(&cle->dls);

		itf_set_state(tunitf, 0);

		if (cle->peer_type != CONF_PEER_TYPE_DBONLY)
			local_del_peer(cle->fingerprint);
	}
}

static void cle_record_received(void *_cle, const uint8_t *rec, int len)
{
	struct conf_listen_entry *cle = _cle;
	int rlen;

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	tun_interface_send_packet(&cle->tun, rec + 3, rlen);
}

static int start_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->tun.itfname = cce->tunitf;
	cce->tun.cookie = cce;
	cce->tun.got_packet = cce_tun_got_packet;
	if (tun_interface_register(&cce->tun) < 0)
		return 1;

	cce->registered = 1;

	itf_set_state(tun_interface_get_name(&cce->tun), 0);

	cce->tc.name = cce->name;
	cce->tc.hostname = cce->hostname;
	cce->tc.port = cce->port;
	cce->tc.privkey = privkey;
	cce->tc.fingerprint = cce->fingerprint;
	cce->tc.cookie = cce;
	cce->tc.set_state = cce_set_state;
	cce->tc.record_received = cce_record_received;
	tconn_connect_start(&cce->tc);

	cce->dc.myid = keyid;
	cce->dc.remoteid = cce->fingerprint;
	cce->dc.ifindex = if_nametoindex(tun_interface_get_name(&cce->tun));
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

	tun_interface_unregister(&cce->tun);
}

static int start_conf_listen_entry(struct conf_listening_socket *cls,
				   struct conf_listen_entry *cle)
{
	cle->tun.itfname = cle->tunitf;
	cle->tun.cookie = cle;
	cle->tun.got_packet = cle_tun_got_packet;
	if (tun_interface_register(&cle->tun) < 0)
		return 1;

	cle->registered = 1;

	itf_set_state(tun_interface_get_name(&cle->tun), 0);

	cle->tle.tls = &cls->tls;
	cle->tle.name = cle->name;
	cle->tle.fingerprint = cle->fingerprint;
	cle->tle.cookie = cle;
	cle->tle.set_state = cle_set_state;
	cle->tle.record_received = cle_record_received;
	tconn_listen_entry_register(&cle->tle);

	cle->dls.myid = keyid;
	cle->dls.ifindex = if_nametoindex(tun_interface_get_name(&cle->tun));
	cle->dls.loc_rib = &loc_rib;
	cle->dls.permit_readonly = 0;

	cle->dle.dls = &cle->dls;
	cle->dle.remoteid = cle->fingerprint;

	return 0;
}

static void stop_conf_listen_entry(struct conf_listen_entry *cle)
{
	cle->registered = 0;

	if (cle->tconn_up) {
		dgp_listen_entry_unregister(&cle->dle);
		dgp_listen_socket_unregister(&cle->dls);
		local_del_peer(cle->fingerprint);
	}

	tconn_listen_entry_unregister(&cle->tle);

	tun_interface_unregister(&cle->tun);
}

static int start_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_avl_node *an;

	cls->tls.listen_address = cls->listen_address;
	cls->tls.privkey = privkey;
	if (tconn_listen_socket_register(&cls->tls))
		return 1;

	cls->registered = 1;

	iv_avl_tree_for_each (an, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_container_of(an, struct conf_listen_entry, an);
		if (start_conf_listen_entry(cls, cle))
			return 1;
	}

	return 0;
}

static void stop_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_avl_node *an;

	cls->registered = 0;

	iv_avl_tree_for_each (an, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_container_of(an, struct conf_listen_entry, an);
		if (cle->registered)
			stop_conf_listen_entry(cle);
	}

	tconn_listen_socket_unregister(&cls->tls);
}

static void stop_config(struct conf *conf)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_container_of(an, struct conf_connect_entry, an);
		if (cce->registered)
			stop_conf_connect_entry(cce);
	}

	iv_avl_tree_for_each (an, &conf->listening_sockets) {
		struct conf_listening_socket *cls;

		cls = iv_container_of(an, struct conf_listening_socket, an);
		if (cls->registered)
			stop_conf_listening_socket(cls);
	}
}

static int start_config(struct conf *conf)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_container_of(an, struct conf_connect_entry, an);
		if (start_conf_connect_entry(cce))
			goto err;
	}

	iv_avl_tree_for_each (an, &conf->listening_sockets) {
		struct conf_listening_socket *cls;

		cls = iv_container_of(an, struct conf_listening_socket, an);
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
	fprintf(stderr, "new peer %s, connect to %s:%s\n", cce->name,
		cce->hostname, cce->port);

	return start_conf_connect_entry(cce);
}

static void removed_connect_entry(struct conf_connect_entry *cce)
{
	fprintf(stderr, "deleted peer %s\n", cce->name);

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
	fprintf(stderr, "new peer %s, listen on ", cle->name);
	print_address(stderr, (const struct sockaddr *)&cls->listen_address);
	fprintf(stderr, "\n");

	return start_conf_listen_entry(cls, cle);
}

static void removed_listen_entry(struct conf_listening_socket *cls,
				 struct conf_listen_entry *cle)
{
	fprintf(stderr, "deleted peer %s\n", cle->name);

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
	loc_rib_print(stderr, &loc_rib);
}

static void usage(const char *me)
{
	fprintf(stderr, "syntax: %s [-c <config.ini>]\n", me);
	fprintf(stderr, "        %s [--show-key-id <key.pem>]\n", me);
}

static int show_key_id(const char *file)
{
	int ret;

	gnutls_global_init();

	ret = x509_read_privkey(&privkey, file);
	if (ret == 0) {
		ret = x509_get_privkey_id(keyid, privkey);
		if (ret == 0) {
			printhex(stdout, keyid, NODE_ID_LEN);
			printf("\n");
		}
		gnutls_x509_privkey_deinit(privkey);
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

	if (x509_read_privkey(&privkey, conf->private_key) < 0)
		return 1;

	if (x509_get_privkey_id(keyid, privkey) < 0)
		return 1;

	fprintf(stderr, "dvpn: using key ID ");
	printhex(stderr, keyid, NODE_ID_LEN);
	fprintf(stderr, "\n");

	iv_init();

	loc_rib.myid = keyid;
	loc_rib_init(&loc_rib);

	rb.rib = &loc_rib;
	rb.myid = keyid;
	rb.cookie = NULL;
	rb.rt_add = rt_add;
	rb.rt_mod = rt_mod;
	rb.rt_del = rt_del;
	rt_builder_init(&rb);

	dls.myid = keyid;
	dls.ifindex = 0;
	dls.loc_rib = &loc_rib;
	dls.permit_readonly = 1;
	if (dgp_listen_socket_register(&dls))
		return 1;

	me = lsa_alloc(keyid);
	lsa_add_attr(me, LSA_ATTR_TYPE_ADV_PATH, NULL, 0, NULL, 0);
	if (conf->node_name != NULL) {
		lsa_add_attr(me, LSA_ATTR_TYPE_NODE_NAME, NULL, 0,
			     conf->node_name, strlen(conf->node_name));
	}
	lsa_initial_version(me);
	lsa_add_pubkey_from_privkey(me, privkey);
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

	loc_rib_del_lsa(&loc_rib, me);
	lsa_put(me);

	rt_builder_deinit(&rb);

	loc_rib_deinit(&loc_rib);

	iv_deinit();

	gnutls_x509_privkey_deinit(privkey);

	gnutls_global_deinit();

	free_config(conf);

	return 0;
}
