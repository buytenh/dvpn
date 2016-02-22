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
#include "util.h"

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

struct cle_op {
	struct confdiff_request		*req;
	struct conf_listening_socket	*cls;
	struct conf_listening_socket	*newcls;
};

static void cle_add(void *_op, struct iv_avl_node *_a)
{
	struct cle_op *op = _op;
	struct conf_listen_entry *a;

	a = iv_container_of(_a, struct conf_listen_entry, an);

	iv_avl_tree_delete(&op->newcls->listen_entries, &a->an);
	iv_avl_tree_insert(&op->cls->listen_entries, &a->an);
	if (op->req->new_listen_entry(op->cls, a)) {
		iv_avl_tree_delete(&op->cls->listen_entries, &a->an);
		iv_avl_tree_insert(&op->newcls->listen_entries, &a->an);
	}
}

static void cle_mod(void *_op, struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct cle_op *op = _op;
	struct conf_listen_entry *a;
	struct conf_listen_entry *b;

	a = iv_container_of(_a, struct conf_listen_entry, an);
	b = iv_container_of(_b, struct conf_listen_entry, an);

	if (!memcmp(a->fingerprint, b->fingerprint, NODE_ID_LEN) &&
	    a->peer_type == b->peer_type && !strcmp(a->tunitf, b->tunitf)) {
		return;
	}

	iv_avl_tree_delete(&op->cls->listen_entries, &a->an);
	op->req->removed_listen_entry(op->cls, a);

	iv_avl_tree_delete(&op->newcls->listen_entries, &b->an);
	iv_avl_tree_insert(&op->cls->listen_entries, &b->an);
	if (op->req->new_listen_entry(op->cls, b)) {
		iv_avl_tree_delete(&op->cls->listen_entries, &b->an);
		iv_avl_tree_insert(&op->newcls->listen_entries, &b->an);

		iv_avl_tree_delete(&op->cls->listen_entries, &a->an);
		if (op->req->new_listen_entry(op->cls, a))
			abort();
	} else {
		iv_avl_tree_insert(&op->newcls->listen_entries, &a->an);
	}
}

static void cle_del(void *_op, struct iv_avl_node *_a)
{
	struct cle_op *op = _op;
	struct conf_listen_entry *a;

	a = iv_container_of(_a, struct conf_listen_entry, an);

	iv_avl_tree_delete(&op->cls->listen_entries, &a->an);
	op->req->removed_listen_entry(op->cls, a);
	iv_avl_tree_insert(&op->newcls->listen_entries, &a->an);
}

static void cls_mod(void *_req, struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct confdiff_request *req = _req;
	struct conf_listening_socket *a;
	struct conf_listening_socket *b;
	struct cle_op op;

	a = iv_container_of(_a, struct conf_listening_socket, an);
	b = iv_container_of(_b, struct conf_listening_socket, an);

	op.req = req;
	op.cls = a;
	op.newcls = b;

	avl_diff(&a->listen_entries, &b->listen_entries, &op,
		 cle_add, cle_mod, cle_del);
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
