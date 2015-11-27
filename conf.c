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
 * - parse [12::34]:5678 IPv6 address/port format properly
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ini_configobj.h>
#include <string.h>
#include <strings.h>
#include "conf.h"

struct local_conf
{
	struct conf	*conf;
	int		default_port;
};

static struct ini_cfgobj *parse_cfgfile(const char *file)
{
	struct ini_cfgobj *co;
	struct ini_cfgfile *cf;

	if (ini_config_create(&co))
		return NULL;

	if (ini_config_file_open(file, 0, &cf)) {
		fprintf(stderr, "error opening %s\n", file);
		ini_config_destroy(co);
		return NULL;
	}

	if (ini_config_parse(cf, INI_STOP_ON_ANY,
			     INI_MS_ERROR | INI_MV1S_ALLOW, 0, co)) {
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
	if (ret == 0) {
		char *key;

		key = ini_get_string_config_value(vo, &ret);
		if (ret)
			return -1;

		lc->conf->private_key = key;
	}

	ret = ini_get_config_valueobj("default", "DefaultPort", co,
				      INI_GET_FIRST_VALUE, &vo);
	if (ret == 0 && vo != NULL) {
		int port;

		port = ini_get_int_config_value(vo, 1, 0, &ret);
		if (ret)
			return -1;

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

static int
add_connect_peer(struct local_conf *lc, const char *peer, const char *connect,
		 const uint8_t *fp, const char *itf)
{
	struct conf_connect_entry *ce;
	const char *colon;
	int port;

	colon = strchr(connect, ':');
	if (colon != NULL) {
		if (sscanf(colon + 1, "%d", &port) != 1)
			return -1;
	} else {
		port = lc->default_port;
	}

	ce = malloc(sizeof(*ce));
	if (ce == NULL)
		return -1;

	ce->name = strdup(peer);
	ce->hostname = strdup(connect);
	if (colon != NULL)
		ce->hostname[colon - connect] = 0;
	asprintf(&ce->port, "%d", port);
	memcpy(ce->fingerprint, fp, 20);
	ce->tunitf = strdup(itf);
	ce->userptr = NULL;

	iv_list_add_tail(&ce->list, &lc->conf->connect_entries);

	return 0;
}

static int parse_listen_addr(struct sockaddr_storage *dst,
			     const char *listen, int default_port)
{
	char *l;
	char *colon;
	int port;
	struct sockaddr_in6 *addr;

	l = strdup(listen);
	if (l == NULL)
		return -1;

	colon = strchr(l, ':');
	if (colon != NULL) {
		if (sscanf(colon + 1, "%d", &port) != 1)
			return -1;
		*colon = 0;
	} else {
		port = default_port;
	}

	// @@@
	if (strcmp(l, "") && strcmp(l, "*")) {
		free(l);
		return -1;
	}

	free(l);

	addr = (struct sockaddr_in6 *)dst;
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(port);
	addr->sin6_flowinfo = 0;
	addr->sin6_addr = in6addr_any;
	addr->sin6_scope_id = 0;

	return 0;
}

static int addr_compare(const struct sockaddr_storage *a,
			const struct sockaddr_storage *b)
{
	if (a->ss_family < b->ss_family)
		return -1;

	if (a->ss_family > b->ss_family)
		return 1;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
		const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
		int ret;

		ret = memcmp(&aa->sin_addr, &bb->sin_addr,
			     sizeof(aa->sin_addr));
		if (ret)
			return ret;

		ret = memcmp(&aa->sin_port, &bb->sin_port,
			     sizeof(aa->sin_port));
		if (ret)
			return ret;

		return 0;
	}

	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
		int ret;

		ret = memcmp(&aa->sin6_addr, &bb->sin6_addr,
			     sizeof(aa->sin6_addr));
		if (ret)
			return ret;

		ret = memcmp(&aa->sin6_port, &bb->sin6_port,
			     sizeof(aa->sin6_port));
		if (ret)
			return ret;

		return 0;
	}

	abort();
}

static struct conf_listening_socket *
get_listening_socket(struct local_conf *lc, const char *listen)
{
	struct sockaddr_storage addr;
	struct iv_list_head *lh;
	struct conf_listening_socket *cls;

	if (parse_listen_addr(&addr, listen, lc->default_port) < 0)
		return NULL;

	iv_list_for_each (lh, &lc->conf->listening_sockets) {
		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		if (addr_compare(&addr, &cls->listen_address) == 0)
			return cls;
	}

	cls = malloc(sizeof(*cls));
	if (cls == NULL)
		return NULL;

	iv_list_add_tail(&cls->list, &lc->conf->listening_sockets);
	cls->listen_address = addr;
	INIT_IV_LIST_HEAD(&cls->listen_entries);
	cls->userptr = NULL;

	return cls;
}

static int
add_listen_peer(struct local_conf *lc, const char *peer, const char *listen,
		const uint8_t *fp, const char *itf)
{
	struct conf_listening_socket *cls;
	struct conf_listen_entry *ce;

	cls = get_listening_socket(lc, listen);
	if (cls == NULL)
		return -1;

	ce = malloc(sizeof(*ce));
	if (ce == NULL)
		return -1;

	iv_list_add_tail(&ce->list, &cls->listen_entries);
	ce->name = strdup(peer);
	memcpy(ce->fingerprint, fp, 20);
	ce->tunitf = strdup(itf);
	ce->userptr = NULL;

	return 0;
}

static int parse_config_peer(struct local_conf *lc,
			     struct ini_cfgobj *co, const char *peer)
{
	const char *connect;
	const char *listen;
	const char *fp;
	const char *itf;
	uint8_t f[20];

	connect = get_const_value(co, peer, "Connect");
	listen = get_const_value(co, peer, "Listen");
	if (!!(connect == NULL) == !!(listen == NULL))
		return -1;

	fp = get_const_value(co, peer, "PeerFingerprint");
	if (fp == NULL)
		return -1;

	if (sscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:"
		       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &f[0], &f[1], &f[2], &f[3], &f[4],
		   &f[5], &f[6], &f[7], &f[8], &f[9],
		   &f[10], &f[11], &f[12], &f[13], &f[14],
		   &f[15], &f[16], &f[17], &f[18], &f[19]) != 20) {
		return -1;
	}

	itf = get_const_value(co, peer, "TunInterface");
	if (itf == NULL)
		return -1;

	if (connect != NULL)
		return add_connect_peer(lc, peer, connect, f, itf);
	else
		return add_listen_peer(lc, peer, listen, f, itf);

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
	if (conf == NULL)
		return NULL;

	conf->private_key = NULL;
	INIT_IV_LIST_HEAD(&conf->connect_entries);
	INIT_IV_LIST_HEAD(&conf->listening_sockets);

	co = parse_cfgfile(file);
	if (co == NULL) {
		free(conf);
		return NULL;
	}

	lc.conf = conf;
	lc.default_port = 0;

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
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	free(conf->private_key);

	iv_list_for_each_safe (lh, lh2, &conf->connect_entries) {
		struct conf_connect_entry *ce;

		ce = iv_list_entry(lh, struct conf_connect_entry, list);

		iv_list_del(&ce->list);
		free(ce->name);
		free(ce->hostname);
		free(ce->port);
		free(ce->tunitf);
		free(ce);
	}

	iv_list_for_each_safe (lh, lh2, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct iv_list_head *lh3;
		struct iv_list_head *lh4;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);

		iv_list_del(&cls->list);

		iv_list_for_each_safe (lh3, lh4, &cls->listen_entries) {
			struct conf_listen_entry *ce;

			ce = iv_list_entry(lh3, struct conf_listen_entry, list);

			iv_list_del(&ce->list);
			free(ce->name);
			free(ce->tunitf);
			free(ce);
		}

		free(cls);
	}

	free(conf);
}
