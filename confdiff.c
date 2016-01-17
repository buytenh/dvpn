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
#include <arpa/inet.h>
#include <string.h>
#include "confdiff.h"

static struct conf_connect_entry *
find_connect_entry(struct conf *conf, struct conf_connect_entry *_cce)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);

		if (strcmp(cce->name, _cce->name))
			continue;
		if (strcmp(cce->hostname, _cce->hostname))
			continue;
		if (strcmp(cce->port, _cce->port))
			continue;
		if (memcmp(cce->fingerprint, _cce->fingerprint, 32))
			continue;
		if (cce->peer_type != _cce->peer_type)
			continue;
		if (strcmp(cce->tunitf, _cce->tunitf))
			continue;

		return cce;
	}

	return NULL;
}

static void diff_connect_entries(struct confdiff_request *req)
{
	struct conf *conf = req->conf;
	struct conf *newconf = req->newconf;
	struct iv_list_head gc;
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	INIT_IV_LIST_HEAD(&gc);

	iv_list_for_each_safe (lh, lh2, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);
		if (find_connect_entry(newconf, cce) == NULL) {
			iv_list_del_init(lh);
			req->removed_connect_entry(cce);
			iv_list_add_tail(lh, &gc);
		}
	}

	iv_list_for_each_safe (lh, lh2, &newconf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);
		if (find_connect_entry(conf, cce) == NULL) {
			iv_list_del(lh);
			iv_list_add_tail(lh, &conf->connect_entries);
			if (req->new_connect_entry(cce)) {
				iv_list_del(lh);
				iv_list_add_tail(lh, &gc);
			}
		}
	}

	iv_list_splice_tail(&gc, &newconf->connect_entries);
}

static struct conf_listening_socket *
find_listening_socket(struct conf *conf, struct sockaddr_storage *_addr)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct sockaddr_storage *addr;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		addr = &cls->listen_address;

		if (addr->ss_family != _addr->ss_family)
			continue;

		if (addr->ss_family == AF_INET) {
			struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
			struct sockaddr_in *_a4 = (struct sockaddr_in *)_addr;

			if (a4->sin_addr.s_addr != _a4->sin_addr.s_addr)
				continue;
			if (a4->sin_port != _a4->sin_port)
				continue;
		} else if (addr->ss_family == AF_INET6) {
			struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;
			struct sockaddr_in6 *_a6 = (struct sockaddr_in6 *)_addr;

			if (memcmp(&a6->sin6_addr, &_a6->sin6_addr, 16))
				continue;
			if (a6->sin6_port != _a6->sin6_port)
				continue;
		} else {
			continue;
		}

		return cls;
	}

	return NULL;
}

static struct conf_listen_entry *
find_listen_entry(struct conf_listening_socket *cls,
		  struct conf_listen_entry *_cle)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);

		if (strcmp(cle->name, _cle->name))
			continue;
		if (memcmp(cle->fingerprint, _cle->fingerprint, 32))
			continue;
		if (cle->peer_type != _cle->peer_type)
			continue;
		if (strcmp(cle->tunitf, _cle->tunitf))
			continue;

		return cle;
	}

	return NULL;
}

static void diff_listen_entries(struct confdiff_request *req,
				struct conf_listening_socket *cls,
				struct conf_listening_socket *newcls)
{
	struct iv_list_head gc;
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	INIT_IV_LIST_HEAD(&gc);

	iv_list_for_each_safe (lh, lh2, &cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (find_listen_entry(newcls, cle) == NULL) {
			iv_list_del_init(lh);
			req->removed_listen_entry(cls, cle);
			iv_list_add_tail(lh, &gc);
		}
	}

	iv_list_for_each_safe (lh, lh2, &newcls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (find_listen_entry(cls, cle) == NULL) {
			iv_list_del(lh);
			iv_list_add_tail(lh, &cls->listen_entries);
			if (req->new_listen_entry(cls, cle)) {
				iv_list_del(lh);
				iv_list_add_tail(lh, &gc);
			}
		}
	}

	iv_list_splice_tail(&gc, &newcls->listen_entries);
}

static void diff_listening_sockets(struct confdiff_request *req)
{
	struct conf *conf = req->conf;
	struct conf *newconf = req->newconf;
	struct iv_list_head gc;
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	INIT_IV_LIST_HEAD(&gc);

	iv_list_for_each_safe (lh, lh2, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct conf_listening_socket *newcls;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);

		newcls = find_listening_socket(newconf, &cls->listen_address);
		if (newcls == NULL) {
			iv_list_del_init(lh);
			req->removed_listening_socket(cls);
			iv_list_add_tail(lh, &gc);
		}
	}

	iv_list_for_each_safe (lh, lh2, &newconf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct conf_listening_socket *newcls;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);
		newcls = find_listening_socket(conf, &cls->listen_address);

		if (newcls == NULL) {
			iv_list_del(lh);
			iv_list_add_tail(lh, &conf->listening_sockets);
			if (req->new_listening_socket(cls)) {
				iv_list_del(lh);
				iv_list_add_tail(lh, &gc);
			}
		}
		else
			diff_listen_entries(req, cls, newcls);
	}

	iv_list_splice_tail(&gc, &newconf->listening_sockets);
}

void diff_configs(struct confdiff_request *req)
{
	diff_connect_entries(req);
	diff_listening_sockets(req);
}
