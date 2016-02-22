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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ini_configobj.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include "conf.h"
#include "util.h"

struct local_conf {
	struct conf	*conf;
	int		default_port;
};

static int
compare_connect_entries(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct conf_connect_entry *a;
	struct conf_connect_entry *b;

	a = iv_container_of(_a, struct conf_connect_entry, an);
	b = iv_container_of(_b, struct conf_connect_entry, an);

	return strcmp(a->name, b->name);
}

static int
compare_listening_sockets(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct conf_listening_socket *a;
	struct conf_listening_socket *b;

	a = iv_container_of(_a, struct conf_listening_socket, an);
	b = iv_container_of(_b, struct conf_listening_socket, an);

	return addrcmp(&a->listen_address, &b->listen_address);
}

static struct ini_cfgobj *parse_cfgfile(const char *file)
{
	struct ini_cfgobj *co;
	struct ini_cfgfile *cf;

	if (ini_config_create(&co)) {
		fprintf(stderr, "error creating ini config object\n");
		return NULL;
	}

	if (ini_config_file_open(file, 0, &cf)) {
		fprintf(stderr, "error opening %s\n", file);
		ini_config_destroy(co);
		return NULL;
	}

	if (ini_config_parse(cf, INI_STOP_ON_ANY,
			     INI_MS_ERROR | INI_MV1S_ALLOW, 0, co)) {
		fprintf(stderr, "error parsing configuration file\n");
		if (ini_config_error_count(co)) {
			char **errors = NULL;

			ini_config_get_errors(co, &errors);
			if (errors != NULL) {
				ini_config_print_errors(stderr, errors);
				ini_config_free_errors(errors);
			}
		}
		ini_config_file_destroy(cf);
		ini_config_destroy(co);
		return NULL;
	}

	ini_config_file_destroy(cf);

	return co;
}

static int parse_config_default(struct local_conf *lc, struct ini_cfgobj *co)
{
	struct value_obj *vo;
	int ret;

	ret = ini_get_config_valueobj("default", "PrivateKey", co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret == 0 && vo != NULL) {
		char *key;

		key = ini_get_string_config_value(vo, &ret);
		if (ret) {
			fprintf(stderr, "error retrieving PrivateKey value\n");
			return -1;
		}

		lc->conf->private_key = key;
	} else {
		lc->conf->private_key = strdup("/etc/pki/tls/dvpn/dvpn.key");
	}

	ret = ini_get_config_valueobj("default", "NodeName", co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret == 0 && vo != NULL) {
		char *key;

		key = ini_get_string_config_value(vo, &ret);
		if (ret) {
			fprintf(stderr, "error retrieving NodeName value\n");
			return -1;
		}

		lc->conf->node_name = key;
	} else {
		struct utsname buf;

		if (uname(&buf) < 0) {
			lc->conf->node_name = NULL;
		} else {
			char *c;

			c = strchr(buf.nodename, '.');
			if (c != NULL)
				*c = 0;

			lc->conf->node_name = strdup(buf.nodename);
		}
	}

	ret = ini_get_config_valueobj("default", "DefaultPort", co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret == 0 && vo != NULL) {
		int port;

		port = ini_get_int_config_value(vo, 1, 0, &ret);
		if (ret) {
			fprintf(stderr, "error retrieving DefaultPort value\n");
			return -1;
		}

		lc->default_port = port;
	}

	return 0;
}

static const char *
get_const_value(struct ini_cfgobj *co, const char *section, const char *name)
{
	struct value_obj *vo;
	int ret;
	const char *value;

	ret = ini_get_config_valueobj(section, name, co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret)
		return NULL;

	value = ini_get_const_string_config_value(vo, &ret);
	if (ret)
		return NULL;

	return value;
}

static enum conf_peer_type parse_peer_type(const char *pt)
{
	if (!strcasecmp(pt, "epeer") || !strcasecmp(pt, "peer"))
		return PEER_TYPE_EPEER;

	if (!strcasecmp(pt, "customer") || !strcasecmp(pt, "downstream"))
		return PEER_TYPE_CUSTOMER;

	if (!strcasecmp(pt, "transit") || !strcasecmp(pt, "upstream"))
		return PEER_TYPE_TRANSIT;

	if (!strcasecmp(pt, "ipeer"))
		return PEER_TYPE_IPEER;

	fprintf(stderr, "error parsing peer type '%s'\n", pt);

	return PEER_TYPE_INVALID;
}

static int
add_connect_peer(struct local_conf *lc, const char *peer, const char *connect,
		 const uint8_t *fp, enum conf_peer_type peer_type,
		 const char *itf, int cost)
{
	struct conf_connect_entry *cce;
	char *delim;
	int port;

	delim = strstr(connect, "]:");
	if (delim != NULL) {
		delim++;
	} else {
		delim = strchr(connect, ':');
		if (delim != NULL && strchr(delim + 1, ':') != NULL)
			delim = NULL;
	}

	if (delim != NULL) {
		if (sscanf(delim + 1, "%d", &port) != 1) {
			fprintf(stderr, "error parsing port number in '%s'\n",
				connect);
			return -1;
		}
	} else {
		port = lc->default_port;
	}

	cce = calloc(1, sizeof(*cce));
	if (cce == NULL) {
		fprintf(stderr, "error allocating memory for cce object\n");
		return -1;
	}

	cce->name = strdup(peer);
	if (iv_avl_tree_insert(&lc->conf->connect_entries, &cce->an) < 0) {
		fprintf(stderr, "found duplicate connect entry '%s'\n", peer);
		free(cce->name);
		return -1;
	}

	if (connect[0] == '[') {
		cce->hostname = strdup(connect + 1);
		delim = strchr(cce->hostname, ']');
		if (delim != NULL)
			*delim = 0;
	} else {
		cce->hostname = strdup(connect);
		if (delim != NULL)
			cce->hostname[delim - connect] = 0;
	}
	asprintf(&cce->port, "%d", port);
	memcpy(cce->fingerprint, fp, NODE_ID_LEN);
	cce->peer_type = peer_type;
	cce->tunitf = strdup(itf ? : "dvpn%d");
	cce->cost = cost;

	return 0;
}

static int parse_listen_addr(struct sockaddr_storage *dst,
			     const char *listen, int default_port)
{
	char *delim;
	int port;
	char *l;
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	int ret;

	delim = strstr(listen, "]:");
	if (delim != NULL) {
		delim++;
	} else {
		delim = strchr(listen, ':');
		if (delim != NULL && strchr(delim + 1, ':') != NULL)
			delim = NULL;
	}

	if (delim != NULL) {
		if (sscanf(delim + 1, "%d", &port) != 1) {
			fprintf(stderr, "error parsing port number in '%s'\n",
				listen);
			return -1;
		}
	} else {
		port = default_port;
	}

	if (listen[0] == '[') {
		l = strdup(listen + 1);
		delim = strchr(l, ']');
		if (delim != NULL)
			*delim = 0;
	} else {
		l = strdup(listen);
		if (delim != NULL)
			l[delim - listen] = 0;
	}

	a6 = (struct sockaddr_in6 *)dst;
	a6->sin6_family = AF_INET6;
	a6->sin6_port = htons(port);
	a6->sin6_flowinfo = 0;
	a6->sin6_scope_id = 0;

	ret = 0;
	if (!strcmp(l, "") || !strcmp(l, "*")) {
		a6->sin6_addr = in6addr_any;
	} else if (!inet_pton(AF_INET6, l, &a6->sin6_addr)) {
		a4 = (struct sockaddr_in *)dst;
		a4->sin_family = AF_INET;
		a4->sin_port = htons(port);

		if (!inet_pton(AF_INET, l, &a4->sin_addr)) {
			fprintf(stderr, "error parsing address '%s'\n", l);
			ret = -1;
		}
	}

	free(l);

	return ret;
}

static int
compare_listen_entries(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct conf_listen_entry *a;
	struct conf_listen_entry *b;

	a = iv_container_of(_a, struct conf_listen_entry, an);
	b = iv_container_of(_b, struct conf_listen_entry, an);

	return strcmp(a->name, b->name);
}

static struct conf_listening_socket *
get_listening_socket(struct local_conf *lc, const char *listen)
{
	struct sockaddr_storage addr;
	struct iv_avl_node *an;
	struct conf_listening_socket *cls;

	if (parse_listen_addr(&addr, listen, lc->default_port) < 0)
		return NULL;

	an = lc->conf->listening_sockets.root;
	while (an != NULL) {
		int ret;

		cls = iv_container_of(an, struct conf_listening_socket, an);

		ret = addrcmp(&addr, &cls->listen_address);
		if (ret == 0)
			return cls;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	cls = calloc(1, sizeof(*cls));
	if (cls == NULL) {
		fprintf(stderr, "error allocating memory for cls object\n");
		return NULL;
	}

	cls->listen_address = addr;
	if (iv_avl_tree_insert(&lc->conf->listening_sockets, &cls->an) < 0)
		abort();

	INIT_IV_AVL_TREE(&cls->listen_entries, compare_listen_entries);

	return cls;
}

static int
add_listen_peer(struct local_conf *lc, const char *peer, const char *listen,
		const uint8_t *fp, enum conf_peer_type peer_type,
		const char *itf, int cost)
{
	struct conf_listening_socket *cls;
	struct conf_listen_entry *cle;

	cls = get_listening_socket(lc, listen);
	if (cls == NULL)
		return -1;

	cle = calloc(1, sizeof(*cle));
	if (cle == NULL) {
		fprintf(stderr, "error allocating memory for cle object\n");
		return -1;
	}

	cle->name = strdup(peer);
	iv_avl_tree_insert(&cls->listen_entries, &cle->an);

	memcpy(cle->fingerprint, fp, NODE_ID_LEN);
	cle->peer_type = peer_type;
	cle->tunitf = strdup(itf ? : "dvpn%d");
	cle->cost = cost;

	return 0;
}

static int parse_config_peer(struct local_conf *lc,
			     struct ini_cfgobj *co, const char *peer)
{
	const char *connect;
	const char *listen;
	const char *fp;
	uint8_t f[NODE_ID_LEN];
	const char *peertype;
	enum conf_peer_type peer_type;
	const char *itf;
	struct value_obj *vo;
	int ret;
	int cost;

	connect = get_const_value(co, peer, "Connect");
	listen = get_const_value(co, peer, "Listen");
	if (!!(connect == NULL) == !!(listen == NULL)) {
		fprintf(stderr, "peer object for '%s' needs either a "
				"Connect or a Listen directive\n", peer);
		return -1;
	}

	fp = get_const_value(co, peer, "PeerFingerprint");
	if (fp == NULL) {
		fprintf(stderr, "peer object for '%s' lacks a "
				"PeerFingerprint directive\n", peer);
		return -1;
	}

	if (sscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:"
		       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:"
		       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:"
		       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &f[0], &f[1], &f[2], &f[3],
		   &f[4], &f[5], &f[6], &f[7],
		   &f[8], &f[9], &f[10], &f[11],
		   &f[12], &f[13], &f[14], &f[15],
		   &f[16], &f[17], &f[18], &f[19],
		   &f[20], &f[21], &f[22], &f[23],
		   &f[24], &f[25], &f[26], &f[27],
		   &f[28], &f[29], &f[30], &f[31]) != NODE_ID_LEN) {
		fprintf(stderr, "peer object for '%s' has an unparseable "
				"PeerFingerprint '%s'\n", peer, fp);
		return -1;
	}

	peertype = get_const_value(co, peer, "PeerType");
	if (peertype != NULL) {
		peer_type = parse_peer_type(peertype);
		if (peer_type == PEER_TYPE_INVALID)
			return -1;
	} else {
		peer_type = (connect != NULL) ?
				PEER_TYPE_TRANSIT :
				PEER_TYPE_CUSTOMER;
	}

	itf = get_const_value(co, peer, "TunInterface");

	ret = ini_get_config_valueobj(peer, "Cost", co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret == 0 && vo != NULL) {
		cost = ini_get_int_config_value(vo, 1, 0, &ret);
		if (ret) {
			fprintf(stderr, "error retrieving Cost value\n");
			return -1;
		}

		if (cost < 1 || cost > 32767) {
			fprintf(stderr, "peer Cost must be in [1..32767]\n");
			return -1;
		}
	} else {
		cost = 1;
	}

	if (connect != NULL) {
		return add_connect_peer(lc, peer, connect, f,
					peer_type, itf, cost);
	} else {
		return add_listen_peer(lc, peer, listen, f,
				       peer_type, itf, cost);
	}

	return 0;
}

struct conf *parse_config(const char *file)
{
	struct conf *conf;
	struct ini_cfgobj *co;
	struct local_conf lc;
	char **section;
	int num_sections;
	int err;

	conf = malloc(sizeof(*conf));
	if (conf == NULL) {
		fprintf(stderr, "error allocating memory for conf object\n");
		return NULL;
	}

	conf->private_key = NULL;
	conf->node_name = NULL;
	INIT_IV_AVL_TREE(&conf->connect_entries, compare_connect_entries);
	INIT_IV_AVL_TREE(&conf->listening_sockets, compare_listening_sockets);

	co = parse_cfgfile(file);
	if (co == NULL) {
		free(conf);
		return NULL;
	}

	lc.conf = conf;
	lc.default_port = 19275;

	if (parse_config_default(&lc, co) < 0) {
		ini_config_destroy(co);
		free(conf);
		return NULL;
	}

	section = ini_get_section_list(co, &num_sections, &err);
	if (section != NULL) {
		int i;

		for (i = 0; i < num_sections; i++) {
			if (strcasecmp(section[i], "default") == 0)
				continue;

			if (parse_config_peer(&lc, co, section[i]) < 0) {
				ini_free_section_list(section);
				ini_config_destroy(co);
				free(conf);
				return NULL;
			}
		}

		ini_free_section_list(section);
	}

	ini_config_destroy(co);

	return conf;
}

void free_config(struct conf *conf)
{
	struct iv_avl_node *an;
	struct iv_avl_node *an2;

	free(conf->private_key);

	free(conf->node_name);

	iv_avl_tree_for_each_safe (an, an2, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_container_of(an, struct conf_connect_entry, an);

		iv_avl_tree_delete(&conf->connect_entries, &cce->an);
		free(cce->name);
		free(cce->hostname);
		free(cce->port);
		free(cce->tunitf);
		free(cce);
	}

	iv_avl_tree_for_each_safe (an, an2, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct iv_avl_node *bn;
		struct iv_avl_node *bn2;

		cls = iv_container_of(an, struct conf_listening_socket, an);

		iv_avl_tree_delete(&conf->listening_sockets, &cls->an);

		iv_avl_tree_for_each_safe (bn, bn2, &cls->listen_entries) {
			struct conf_listen_entry *cle;

			cle = iv_container_of(bn, struct conf_listen_entry, an);

			iv_avl_tree_delete(&cls->listen_entries, &cle->an);
			free(cle->name);
			free(cle->tunitf);
			free(cle);
		}

		free(cls);
	}

	free(conf);
}
