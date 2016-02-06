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

static void cce_add(void *_req, struct iv_avl_node *_a)
{
	struct confdiff_request *req = _req;
	struct conf_connect_entry *a;

	a = iv_container_of(_a, struct conf_connect_entry, an);

	iv_avl_tree_delete(&req->newconf->connect_entries, &a->an);
	iv_avl_tree_insert(&req->conf->connect_entries, &a->an);
	if (req->new_connect_entry(a)) {
		iv_avl_tree_delete(&req->conf->connect_entries, &a->an);
		iv_avl_tree_insert(&req->newconf->connect_entries, &a->an);
	}
}

static void cce_mod(void *_req, struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct confdiff_request *req = _req;
	struct conf_connect_entry *a;
	struct conf_connect_entry *b;

	a = iv_container_of(_a, struct conf_connect_entry, an);
	b = iv_container_of(_b, struct conf_connect_entry, an);

	if (!strcmp(a->hostname, b->hostname) && !strcmp(a->port, b->port) &&
	    !memcmp(a->fingerprint, b->fingerprint, NODE_ID_LEN) &&
	    a->peer_type == b->peer_type && !strcmp(a->tunitf, b->tunitf) &&
	    a->cost == b->cost) {
		return;
	}

	iv_avl_tree_delete(&req->conf->connect_entries, &a->an);
	req->removed_connect_entry(a);

	iv_avl_tree_delete(&req->newconf->connect_entries, &b->an);
	iv_avl_tree_insert(&req->conf->connect_entries, &b->an);
	if (req->new_connect_entry(b)) {
		iv_avl_tree_delete(&req->conf->connect_entries, &b->an);
		iv_avl_tree_insert(&req->newconf->connect_entries, &b->an);

		iv_avl_tree_insert(&req->conf->connect_entries, &a->an);
		if (req->new_connect_entry(a))
			abort();
	} else {
		iv_avl_tree_insert(&req->newconf->connect_entries, &a->an);
	}
}

static void cce_del(void *_req, struct iv_avl_node *_a)
{
	struct confdiff_request *req = _req;
	struct conf_connect_entry *a;

	a = iv_container_of(_a, struct conf_connect_entry, an);

	iv_avl_tree_delete(&req->conf->connect_entries, &a->an);
	req->removed_connect_entry(a);
	iv_avl_tree_insert(&req->newconf->connect_entries, &a->an);
}

static void cls_add(void *_req, struct iv_avl_node *_a)
{
	struct confdiff_request *req = _req;
	struct conf_listening_socket *a;

	a = iv_container_of(_a, struct conf_listening_socket, an);

	iv_avl_tree_delete(&req->newconf->listening_sockets, &a->an);
	iv_avl_tree_insert(&req->conf->listening_sockets, &a->an);
	if (req->new_listening_socket(a)) {
		iv_avl_tree_delete(&req->conf->listening_sockets, &a->an);
		iv_avl_tree_insert(&req->newconf->listening_sockets, &a->an);
	}
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
		if (memcmp(cle->fingerprint, _cle->fingerprint, NODE_ID_LEN))
			continue;
		if (cle->peer_type != _cle->peer_type)
			continue;
		if (strcmp(cle->tunitf, _cle->tunitf))
			continue;

		return cle;
	}

	return NULL;
}

static void cls_mod(void *_req, struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct confdiff_request *req = _req;
	struct conf_listening_socket *a;
	struct conf_listening_socket *b;
	struct iv_list_head gc;
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	a = iv_container_of(_a, struct conf_listening_socket, an);
	b = iv_container_of(_b, struct conf_listening_socket, an);

	INIT_IV_LIST_HEAD(&gc);

	iv_list_for_each_safe (lh, lh2, &a->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (find_listen_entry(b, cle) == NULL) {
			iv_list_del_init(lh);
			req->removed_listen_entry(a, cle);
			iv_list_add_tail(lh, &gc);
		}
	}

	iv_list_for_each_safe (lh, lh2, &b->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (find_listen_entry(a, cle) == NULL) {
			iv_list_del(lh);
			iv_list_add_tail(lh, &a->listen_entries);
			if (req->new_listen_entry(a, cle)) {
				iv_list_del(lh);
				iv_list_add_tail(lh, &gc);
			}
		}
	}

	iv_list_splice_tail(&gc, &b->listen_entries);
}

static void cls_del(void *_req, struct iv_avl_node *_a)
{
	struct confdiff_request *req = _req;
	struct conf_listening_socket *a;

	a = iv_container_of(_a, struct conf_listening_socket, an);

	iv_avl_tree_delete(&req->conf->listening_sockets, &a->an);
	req->removed_listening_socket(a);
	iv_avl_tree_insert(&req->newconf->listening_sockets, &a->an);
}

void diff_configs(struct confdiff_request *req)
{
	avl_diff(&req->conf->connect_entries,
		 &req->newconf->connect_entries,
		 req, cce_add, cce_mod, cce_del);

	avl_diff(&req->conf->listening_sockets,
		 &req->newconf->listening_sockets,
		 req, cls_add, cls_mod, cls_del);
}
