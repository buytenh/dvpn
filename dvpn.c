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
#include <gnutls/abstract.h>
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
static gnutls_x509_privkey_t rolekey;
static uint8_t keyid[NODE_ID_LEN];
static int numcrts;
static gnutls_x509_crt_t crt[2];
static struct loc_rib loc_rib;
static struct rt_builder rb;
static struct iv_avl_tree direct_peers;
static struct dgp_listen_socket dls;
static struct lsa *me;

static struct direct_peer *dp_find(uint8_t *addr)
{
	struct iv_avl_node *an;

	an = direct_peers.root;
	while (an != NULL) {
		struct direct_peer *dp;
		int ret;

		dp = iv_container_of(an, struct direct_peer, an);

		ret = memcmp(addr, dp->addr, sizeof(dp->addr));
		if (ret == 0)
			return dp;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static char *peer_itfname(uint8_t *addr)
{
	struct direct_peer *dp;

	dp = dp_find(addr);
	if (dp != NULL)
		return dp->itfname;

	return NULL;
}

static void rt_add(void *_dummy, uint8_t *dest, uint8_t *nh)
{
	if (nh != NULL)
		itf_add_route_v6_direct(dest, peer_itfname(nh));
	else
		itf_add_route_v6_direct(dest, peer_itfname(dest));
}

static void rt_mod(void *_dummy, uint8_t *dest, uint8_t *oldnh, uint8_t *newnh)
{
	const char *itfname;

	if (newnh != NULL)
		itfname = peer_itfname(newnh);
	else
		itfname = peer_itfname(dest);

	if (itf_chg_route_v6_direct(dest, itfname) < 0)
		itf_add_route_v6_direct(dest, itfname);
}

static void rt_del(void *_dummy, uint8_t *dest, uint8_t *nh)
{
	const char *itfname;

	if (nh != NULL)
		itfname = peer_itfname(nh);
	else
		itfname = peer_itfname(dest);

	if (itfname != NULL)
		itf_del_route_v6_direct(dest, itfname);
}

static int compare_direct_peers(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct direct_peer *a;
	struct direct_peer *b;

	a = iv_container_of(_a, struct direct_peer, an);
	b = iv_container_of(_b, struct direct_peer, an);

	return memcmp(a->addr, b->addr, sizeof(a->addr));
}

static enum lsa_peer_flags
conf_peer_type_to_lsa_peer_flags(enum conf_peer_type type)
{
	switch (type) {
	case CONF_PEER_TYPE_EPEER:
		return 0;
	case CONF_PEER_TYPE_CUSTOMER:
		return LSA_PEER_FLAGS_CUSTOMER;
	case CONF_PEER_TYPE_TRANSIT:
		return LSA_PEER_FLAGS_TRANSIT;
	case CONF_PEER_TYPE_IPEER:
		return LSA_PEER_FLAGS_CUSTOMER | LSA_PEER_FLAGS_TRANSIT;
	default:
		fprintf(stderr, "conf_peer_type_to_lsa_peer_flags: invalid "
				"type %d\n", type);
		abort();
	}
}

static void lsa_add_version(struct lsa *lsa, uint64_t version)
{
	uint32_t t32[2];

	t32[0] = htonl((version >> 32) & 0xffffffff);
	t32[1] = htonl(version & 0xffffffff);
	lsa_add_attr(lsa, LSA_ATTR_TYPE_VERSION, 1, NULL, 0, t32, sizeof(t32));
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

static void lsa_add_pubkey(struct lsa *lsa)
{
	uint8_t buf[65536];
	int len;

	len = x509_privkey_to_der_pubkey(buf, sizeof(buf), privkey);
	if (len < 0)
		abort();

	lsa_add_attr(lsa, LSA_ATTR_TYPE_PUBKEY, 1, NULL, 0, buf, len);
}

static void lsa_sign(struct lsa *lsa)
{
	struct lsa_attr *attr;
	size_t serlen;
	size_t buflen;
	void *buf;
	size_t len;
	gnutls_privkey_t pk;
	int ret;
	gnutls_datum_t data;
	gnutls_datum_t sig;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_SIGNATURE, NULL, 0);
	if (attr != NULL)
		lsa_del_attr(lsa, attr);

	serlen = lsa_serialise_length(lsa, 1, NULL);
	if (serlen > 65536 - 128)
		abort();

	buflen = serlen + 128;
	buf = alloca(buflen);

	len = lsa_serialise(buf, buflen, serlen, lsa, 1, NULL);
	if (len > buflen)
		abort();

	ret = gnutls_privkey_init(&pk);
	if (ret < 0)
		abort();

	ret = gnutls_privkey_import_x509(pk, privkey, 0);
	if (ret < 0)
		abort();

	data.data = buf;
	data.size = len;
	ret = gnutls_privkey_sign_data(pk, GNUTLS_DIG_SHA256, 0, &data, &sig);
	if (ret < 0)
		abort();

	gnutls_privkey_deinit(pk);

	lsa_add_attr(lsa, LSA_ATTR_TYPE_SIGNATURE, 0, NULL, 0,
		     sig.data, sig.size);

	gnutls_free(sig.data);
}

static void
mylsa_add_peer(const uint8_t *id, enum conf_peer_type type, int cost)
{
	struct lsa *newme;
	struct lsa_attr_set *set;
	uint16_t metric;
	uint8_t peer_flags;

	newme = lsa_clone(me);

	set = lsa_add_attr_set(newme, LSA_ATTR_TYPE_PEER, 1, id, NODE_ID_LEN);

	metric = htons(cost);
	lsa_attr_set_add_attr(newme, set, LSA_PEER_ATTR_TYPE_METRIC, 1,
			      NULL, 0, &metric, sizeof(metric));

	peer_flags = conf_peer_type_to_lsa_peer_flags(type);
	lsa_attr_set_add_attr(newme, set, LSA_PEER_ATTR_TYPE_PEER_FLAGS, 1,
			      NULL, 0, &peer_flags, sizeof(peer_flags));

	lsa_update_version(newme);

	lsa_sign(newme);

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

static void mylsa_del_peer(const uint8_t *id)
{
	struct lsa *newme;

	newme = lsa_clone(me);

	lsa_del_attr_bykey(newme, LSA_ATTR_TYPE_PEER, id, NODE_ID_LEN);

	lsa_update_version(newme);

	lsa_sign(newme);

	loc_rib_mod_lsa(&loc_rib, me, newme);

	lsa_put(me);
	me = newme;
}

struct connect_entry_conn {
	struct iv_list_head		list;

	struct conf_connect_entry	*cce;
	void				*conn;
	uint8_t				peerid[NODE_ID_LEN];

	struct tun_interface		tun;
	struct direct_peer		dp;
	struct dgp_connect		dc;
};

static void cec_tun_got_packet(void *_cec, uint8_t *buf, int len)
{
	struct connect_entry_conn *cec = _cec;
	uint8_t sndbuf[len + 3];

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	tconn_connect_record_send(cec->conn, sndbuf, len + 3);
}

static void cec_destroy(struct connect_entry_conn *cec)
{
	iv_list_del(&cec->list);

	dgp_connect_stop(&cec->dc);

	iv_avl_tree_delete(&direct_peers, &cec->dp.an);

	tun_interface_unregister(&cec->tun);

	if (cec->cce->peer_type != CONF_PEER_TYPE_DBONLY)
		mylsa_del_peer(cec->peerid);

	free(cec);
}

static void *cce_new_conn(void *_cce, void *conn, const uint8_t *id)
{
	struct conf_connect_entry *cce = _cce;
	uint8_t addr[16];
	struct connect_entry_conn *cec;
	int maxseg;
	int mtu;
	char *tunitf;

	v6_global_addr_from_key_id(addr, keyid);
	if (dp_find(addr) != NULL)
		return NULL;

	cec = calloc(1, sizeof(*cec));
	if (cec == NULL)
		return NULL;

	cec->cce = cce;
	cec->conn = conn;
	memcpy(cec->peerid, id, NODE_ID_LEN);

	cec->tun.itfname = cce->tunitf;
	cec->tun.cookie = cec;
	cec->tun.got_packet = cec_tun_got_packet;
	if (tun_interface_register(&cec->tun) < 0) {
		free(cec);
		return NULL;
	}

	if (cce->peer_type != CONF_PEER_TYPE_DBONLY) {
		int cost;

		cost = cce->cost;
		if (cost == 0) {
			cost = tconn_connect_get_rtt(conn);
			if (cost < 1)
				cost = 1;
		}

		mylsa_add_peer(cec->peerid, cce->peer_type, cost);
	}

	maxseg = tconn_connect_get_maxseg(conn);
	if (maxseg < 0)
		abort();

	mtu = maxseg - 5 - 8 - 3 - 16;
	if (mtu < 1280)
		mtu = 1280;
	else if (mtu > 1500)
		mtu = 1500;

	fprintf(stderr, "%s: setting interface MTU to %d\n", cce->name, mtu);

	tunitf = tun_interface_get_name(&cec->tun);

	itf_set_mtu(tunitf, mtu);

	itf_set_state(tunitf, 1);

	v6_linklocal_addr_from_key_id(addr, keyid);
	itf_add_addr_v6(tunitf, addr, 10);

	v6_global_addr_from_key_id(addr, keyid);
	itf_add_addr_v6(tunitf, addr, 128);

	v6_global_addr_from_key_id(cec->dp.addr, id);
	cec->dp.itfname = tunitf;
	if (iv_avl_tree_insert(&direct_peers, &cec->dp.an))
		abort();

	cec->dc.myid = keyid;
	cec->dc.remoteid = cec->peerid;
	cec->dc.ifindex = if_nametoindex(tunitf);
	cec->dc.loc_rib = &loc_rib;
	dgp_connect_start(&cec->dc);

	iv_list_add_tail(&cec->list, &cce->connections);

	return cec;
}

static void cec_record_received(void *_cec, const uint8_t *rec, int len)
{
	struct connect_entry_conn *cec = _cec;
	int rlen;

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	tun_interface_send_packet(&cec->tun, rec + 3, rlen);
}

static void cec_disconnect(void *_cec)
{
	struct connect_entry_conn *cec = _cec;

	cec_destroy(cec);
}

struct listen_entry_conn {
	struct iv_list_head		list;

	struct conf_listen_entry	*cle;
	void				*conn;
	uint8_t				peerid[NODE_ID_LEN];

	struct tun_interface		tun;
	struct direct_peer		dp;
	struct dgp_listen_socket	dls;
	struct dgp_listen_entry		dle;
};

static void lec_tun_got_packet(void *_lec, uint8_t *buf, int len)
{
	struct listen_entry_conn *lec = _lec;
	uint8_t sndbuf[len + 3];

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	tconn_listen_entry_record_send(lec->conn, sndbuf, len + 3);
}

static void lec_destroy(struct listen_entry_conn *lec, int disconnect_tconn)
{
	iv_list_del(&lec->list);

	lec->cle->num_connections--;

	dgp_listen_entry_unregister(&lec->dle);
	dgp_listen_socket_unregister(&lec->dls);

	if (disconnect_tconn)
		tconn_listen_entry_disconnect(lec->conn);

	iv_avl_tree_delete(&direct_peers, &lec->dp.an);

	tun_interface_unregister(&lec->tun);

	if (lec->cle->peer_type != CONF_PEER_TYPE_DBONLY)
		mylsa_del_peer(lec->peerid);

	free(lec);
}

static void *cle_new_conn(void *_cle, void *conn, const uint8_t *id)
{
	struct conf_listen_entry *cle = _cle;
	uint8_t addr[16];
	struct listen_entry_conn *lec;
	int maxseg;
	int mtu;
	char *tunitf;

	v6_global_addr_from_key_id(addr, id);
	if (dp_find(addr) != NULL)
		return NULL;

	lec = calloc(1, sizeof(*lec));
	if (lec == NULL)
		return NULL;

	lec->cle = cle;
	lec->conn = conn;
	memcpy(lec->peerid, id, NODE_ID_LEN);

	lec->tun.itfname = cle->tunitf;
	lec->tun.cookie = lec;
	lec->tun.got_packet = lec_tun_got_packet;
	if (tun_interface_register(&lec->tun) < 0) {
		free(lec);
		return NULL;
	}

	if (cle->conn_limit == cle->num_connections) {
		struct listen_entry_conn *oldlec;

		fprintf(stderr, "%s: connection limit reached, disconnecting "
				"previous client\n", cle->name);

		oldlec = iv_list_entry(cle->connections.prev,
				       struct listen_entry_conn, list);
		lec_destroy(oldlec, 1);
	}

	if (cle->peer_type != CONF_PEER_TYPE_DBONLY) {
		int cost;

		cost = cle->cost;
		if (cost == 0) {
			cost = tconn_listen_entry_get_rtt(conn);
			if (cost < 1)
				cost = 1;
		}

		mylsa_add_peer(lec->peerid, cle->peer_type, cost);
	}

	maxseg = tconn_listen_entry_get_maxseg(conn);
	if (maxseg < 0)
		abort();

	mtu = maxseg - 5 - 8 - 3 - 16;
	if (mtu < 1280)
		mtu = 1280;
	else if (mtu > 1500)
		mtu = 1500;

	fprintf(stderr, "%s: setting interface MTU to %d\n", cle->name, mtu);

	tunitf = tun_interface_get_name(&lec->tun);

	itf_set_mtu(tunitf, mtu);

	itf_set_state(tunitf, 1);

	v6_linklocal_addr_from_key_id(addr, keyid);
	itf_add_addr_v6(tunitf, addr, 10);

	v6_global_addr_from_key_id(addr, keyid);
	itf_add_addr_v6(tunitf, addr, 128);

	v6_global_addr_from_key_id(lec->dp.addr, id);
	lec->dp.itfname = tunitf;
	if (iv_avl_tree_insert(&direct_peers, &lec->dp.an))
		abort();

	lec->dls.myid = keyid;
	lec->dls.ifindex = if_nametoindex(tunitf);
	lec->dls.loc_rib = &loc_rib;
	lec->dls.permit_readonly = 0;
	dgp_listen_socket_register(&lec->dls);

	lec->dle.dls = &lec->dls;
	lec->dle.remoteid = lec->peerid;
	dgp_listen_entry_register(&lec->dle);

	cle->num_connections++;
	iv_list_add_tail(&lec->list, &cle->connections);

	return lec;
}

static void lec_record_received(void *_lec, const uint8_t *rec, int len)
{
	struct listen_entry_conn *lec = _lec;
	int rlen;

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	tun_interface_send_packet(&lec->tun, rec + 3, rlen);
}

static void lec_disconnect(void *_lec)
{
	struct listen_entry_conn *lec = _lec;

	lec_destroy(lec, 0);
}

static int start_conf_connect_entry(struct conf_connect_entry *cce)
{
	cce->registered = 1;

	cce->tc.name = cce->name;
	cce->tc.hostname = cce->hostname;
	cce->tc.port = cce->port;
	cce->tc.mykey = privkey;
	cce->tc.numcrts = numcrts;
	cce->tc.mycrts = crt;
	cce->tc.fp_type = cce->fp_type;
	cce->tc.fingerprint = cce->fingerprint;
	cce->tc.cookie = cce;
	cce->tc.new_conn = cce_new_conn;
	cce->tc.record_received = cec_record_received;
	cce->tc.disconnect = cec_disconnect;
	tconn_connect_start(&cce->tc);

	INIT_IV_LIST_HEAD(&cce->connections);

	return 0;
}

static void stop_conf_connect_entry(struct conf_connect_entry *cce)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	cce->registered = 0;

	iv_list_for_each_safe(lh, lh2, &cce->connections) {
		struct connect_entry_conn *cec;

		cec = iv_list_entry(lh, struct connect_entry_conn, list);
		cec_destroy(cec);
	}

	tconn_connect_destroy(&cce->tc);
}

static int start_conf_listen_entry(struct conf_listening_socket *cls,
				   struct conf_listen_entry *cle)
{
	cle->registered = 1;

	cle->tle.tls = &cls->tls;
	cle->tle.name = cle->name;
	cle->tle.fp_type = cle->fp_type;
	cle->tle.fingerprint = cle->fingerprint;
	cle->tle.cookie = cle;
	cle->tle.new_conn = cle_new_conn;
	cle->tle.record_received = lec_record_received;
	cle->tle.disconnect = lec_disconnect;
	tconn_listen_entry_register(&cle->tle);

	cle->num_connections = 0;

	INIT_IV_LIST_HEAD(&cle->connections);

	return 0;
}

static void stop_conf_listen_entry(struct conf_listen_entry *cle)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	cle->registered = 0;

	iv_list_for_each_safe (lh, lh2, &cle->connections) {
		struct listen_entry_conn *lec;

		lec = iv_list_entry(lh, struct listen_entry_conn, list);
		lec_destroy(lec, 1);
	}

	tconn_listen_entry_unregister(&cle->tle);
}

static int start_conf_listening_socket(struct conf_listening_socket *cls)
{
	struct iv_avl_node *an;

	cls->tls.listen_address = cls->listen_address;
	cls->tls.mykey = privkey;
	cls->tls.numcrts = numcrts;
	cls->tls.mycrts = crt;
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

	rt_builder_deinit(&rb);

	stop_config(conf);

	dgp_listen_socket_unregister(&dls);
}

static void got_sigusr1(void *_dummy)
{
	loc_rib_print(stderr, &loc_rib);
}

int dvpn(const char *_config)
{
	config = _config;

	conf = parse_config(config);
	if (conf == NULL)
		return 1;

	gnutls_global_init();

	if (x509_read_privkey(&rolekey, conf->role_key, 1) < 0)
		return 1;

	if (rolekey != NULL) {
		if (x509_read_privkey(&privkey, conf->private_key, 1) < 0)
			return 1;

		if (privkey == NULL) {
			int ret;

			fprintf(stderr, "dvpn: no valid PrivateKey specified, "
					"generating one\n");

			ret = gnutls_x509_privkey_init(&privkey);
			if (ret < 0) {
				fprintf(stderr, "gnutls_x509_privkey_init: ");
				gnutls_perror(ret);
				return 1;
			}

			ret = gnutls_x509_privkey_generate(privkey,
							   GNUTLS_PK_RSA,
							   4096, 0);
			if (ret < 0) {
				fprintf(stderr,
					"gnutls_x509_privkey_generate: ");
				gnutls_perror(ret);
				return 1;
			}
		}
	} else {
		if (x509_read_privkey(&privkey, conf->private_key, 0) < 0)
			return 1;
	}

	if (x509_get_privkey_id(keyid, privkey) < 0)
		return 1;

	if (x509_generate_self_signed_cert(&crt[0], privkey) < 0)
		return 1;

	if (rolekey != NULL) {
		numcrts = 2;
		if (x509_generate_role_cert(&crt[1], privkey, rolekey) < 0)
			return 1;
	} else {
		numcrts = 1;
	}

	fprintf(stderr, "dvpn: using key ID ");
	print_fingerprint(stderr, keyid);
	fprintf(stderr, "\n");

	if (rolekey != NULL) {
		uint8_t rolekeyid[NODE_ID_LEN];

		if (x509_get_privkey_id(rolekeyid, rolekey) < 0)
			return 1;

		fprintf(stderr, "dvpn: using role key ID ");
		print_fingerprint(stderr, rolekeyid);
		fprintf(stderr, "\n");
	}

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

	INIT_IV_AVL_TREE(&direct_peers, compare_direct_peers);

	dls.myid = keyid;
	dls.ifindex = 0;
	dls.loc_rib = &loc_rib;
	dls.permit_readonly = 1;
	if (dgp_listen_socket_register(&dls))
		return 1;

	me = lsa_alloc(keyid);
	lsa_add_attr(me, LSA_ATTR_TYPE_ADV_PATH, 0, NULL, 0, NULL, 0);
	if (conf->node_name != NULL) {
		lsa_add_attr(me, LSA_ATTR_TYPE_NODE_NAME, 1, NULL, 0,
			     conf->node_name, strlen(conf->node_name));
	}
	lsa_initial_version(me);
	lsa_add_pubkey(me);
	lsa_sign(me);

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

	loc_rib_deinit(&loc_rib);

	iv_deinit();

	gnutls_x509_crt_deinit(crt[0]);
	if (numcrts == 2)
		gnutls_x509_crt_deinit(crt[1]);

	if (rolekey != NULL)
		gnutls_x509_privkey_deinit(rolekey);

	gnutls_x509_privkey_deinit(privkey);

	gnutls_global_deinit();

	free_config(conf);

	return 0;
}
