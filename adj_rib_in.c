/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2016 Lennert Buytenhek
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
#include <iv_avl.h>
#include <iv_list.h>
#include <nettle/sha2.h>
#include <gnutls/abstract.h>
#include <string.h>
#include "adj_rib_in.h"
#include "lsa_diff.h"
#include "lsa_path.h"
#include "lsa_serialise.h"
#include "lsa_type.h"
#include "util.h"

struct adj_rib_in_lsa_ref {
	struct iv_avl_node	an;
	struct lsa		*lsa;
};

static int compare_refs(struct iv_avl_node *_a, struct iv_avl_node *_b)
{
	struct adj_rib_in_lsa_ref *a;
	struct adj_rib_in_lsa_ref *b;

	a = iv_container_of(_a, struct adj_rib_in_lsa_ref, an);
	b = iv_container_of(_b, struct adj_rib_in_lsa_ref, an);

	return memcmp(a->lsa->id, b->lsa->id, NODE_ID_LEN);
}

void adj_rib_in_init(struct adj_rib_in *rib)
{
	INIT_IV_AVL_TREE(&rib->lsas, compare_refs);
	rib->size = 0;
	INIT_IV_LIST_HEAD(&rib->listeners);
}

static struct adj_rib_in_lsa_ref *
adj_rib_in_find_ref(struct adj_rib_in *rib, uint8_t *id)
{
	struct iv_avl_node *an;

	an = rib->lsas.root;
	while (an != NULL) {
		struct adj_rib_in_lsa_ref *ref;
		int ret;

		ref = iv_container_of(an, struct adj_rib_in_lsa_ref, an);

		ret = memcmp(id, ref->lsa->id, NODE_ID_LEN);
		if (ret == 0)
			return ref;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static struct lsa *map(struct adj_rib_in *rib, struct lsa *lsa)
{
	struct lsa_attr *attr;
	struct sha256_ctx ctx;
	uint8_t id[NODE_ID_LEN];
	gnutls_pubkey_t pubkey;
	int ret;
	gnutls_datum_t datum;
	size_t serlen;
	size_t buflen;
	void *buf;
	size_t len;
	gnutls_datum_t data;

	if (lsa == NULL)
		return NULL;

	if (lsa->bytes + NODE_ID_LEN > LSA_MAX_BYTES)
		return NULL;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_ADV_PATH, NULL, 0);
	if (attr == NULL)
		return NULL;

	if (attr->datalen < NODE_ID_LEN || (attr->datalen % NODE_ID_LEN) != 0)
		return NULL;

	if (rib->remoteid == NULL ||
	    memcmp(rib->remoteid, lsa_attr_data(attr), NODE_ID_LEN))
		return NULL;

	if (rib->myid != NULL && lsa_path_contains(attr, rib->myid))
		return NULL;

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_PUBKEY, NULL, 0);
	if (attr == NULL)
		return NULL;

	sha256_init(&ctx);
	sha256_update(&ctx, attr->datalen, lsa_attr_data(attr));
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, id);

	if (memcmp(lsa->id, id, NODE_ID_LEN))
		return NULL;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0) {
		gnutls_perror(ret);
		return NULL;
	}

	datum.data = lsa_attr_data(attr);
	datum.size = attr->datalen;

	ret = gnutls_pubkey_import(pubkey, &datum, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_perror(ret);
		gnutls_pubkey_deinit(pubkey);
		return NULL;
	}

	attr = lsa_find_attr(lsa, LSA_ATTR_TYPE_SIGNATURE, NULL, 0);
	if (attr == NULL) {
		gnutls_pubkey_deinit(pubkey);
		return NULL;
	}

	datum.data = lsa_attr_data(attr);
	datum.size = attr->datalen;

	serlen = lsa_serialise_length(lsa, 1, NULL);
	if (serlen > 65536 - 128)
		abort();

	buflen = serlen + 128;
	buf = alloca(buflen);

	len = lsa_serialise(buf, buflen, serlen, lsa, 1, NULL);
	if (len > buflen)
		abort();

	data.data = buf;
	data.size = len;

	ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256,
					 0, &data, &datum);
	if (ret < 0) {
		gnutls_perror(ret);
		gnutls_pubkey_deinit(pubkey);
		return NULL;
	}

	gnutls_pubkey_deinit(pubkey);

	return lsa;
}

static void notify(struct adj_rib_in *rib, struct lsa *old, struct lsa *new)
{
	struct iv_list_head *ilh;
	struct iv_list_head *ilh2;
	struct rib_listener *rl;

	old = map(rib, old);
	new = map(rib, new);

	if (old != NULL)
		rib->size -= old->bytes;
	if (new != NULL)
		rib->size += new->bytes;

	if (old == NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_add(rl->cookie, new, RIB_COST_UNREACHABLE);
		}
	} else if (old != NULL && new != NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_mod(rl->cookie, old, RIB_COST_UNREACHABLE,
				    new, RIB_COST_UNREACHABLE);
		}
	} else if (old != NULL && new == NULL) {
		iv_list_for_each_safe (ilh, ilh2, &rib->listeners) {
			rl = iv_container_of(ilh, struct rib_listener, list);
			rl->lsa_del(rl->cookie, old, RIB_COST_UNREACHABLE);
		}
	}
}

static void
adj_rib_in_del_lsa(struct adj_rib_in *rib, struct adj_rib_in_lsa_ref *ref)
{
	notify(rib, ref->lsa, NULL);

	iv_avl_tree_delete(&rib->lsas, &ref->an);
	lsa_put(ref->lsa);
	free(ref);
}

int adj_rib_in_add_lsa(struct adj_rib_in *rib, struct lsa *lsa)
{
	struct adj_rib_in_lsa_ref *ref;

	ref = adj_rib_in_find_ref(rib, lsa->id);

	if (iv_avl_tree_empty(&lsa->root.attrs)) {
		if (ref == NULL)
			return -1;

		adj_rib_in_del_lsa(rib, ref);
		return 0;
	}

	if (rib->size + lsa->bytes > ADJ_RIB_IN_MAX_BYTES) {
		fprintf(stderr, "adj_rib_in_add_lsa: dropping LSA "
				"received from peer ");
		printhex(stderr, rib->remoteid, NODE_ID_LEN);
		fprintf(stderr, " because of RIB overflow\n");

		if (ref != NULL)
			adj_rib_in_del_lsa(rib, ref);

		return -1;
	}

	if (ref == NULL) {
		ref = malloc(sizeof(*ref));
		if (ref == NULL) {
			fprintf(stderr, "adj_rib_in_add_lsa: memory "
					"allocation failure\n");
			return -1;
		}

		notify(rib, NULL, lsa);

		ref->lsa = lsa_get(lsa);
		iv_avl_tree_insert(&rib->lsas, &ref->an);
	} else if (lsa_diff(ref->lsa, lsa, NULL, NULL, NULL, NULL)) {
		notify(rib, ref->lsa, lsa);

		lsa_put(ref->lsa);
		ref->lsa = lsa_get(lsa);
	}

	return 0;
}

void adj_rib_in_truncate(struct adj_rib_in *rib)
{
	while (rib->lsas.root != NULL) {
		struct adj_rib_in_lsa_ref *ref;

		ref = iv_container_of(rib->lsas.root,
				      struct adj_rib_in_lsa_ref, an);

		adj_rib_in_del_lsa(rib, ref);
	}
}

void
adj_rib_in_listener_register(struct adj_rib_in *rib, struct rib_listener *rl)
{
	iv_list_add_tail(&rl->list, &rib->listeners);
}

void
adj_rib_in_listener_unregister(struct adj_rib_in *rib, struct rib_listener *rl)
{
	iv_list_del(&rl->list);
}
