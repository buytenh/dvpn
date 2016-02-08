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
#include <ctype.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <iv_list.h>
#include "loc_rib.h"
#include "lsa_print.h"
#include "lsa_type.h"
#include "util.h"

static char *lsa_attr_type_name(int type, char *buf, int bufsize)
{
	switch (type) {
	case LSA_ATTR_TYPE_ADV_PATH:
		return "ADV_PATH";
	case LSA_ATTR_TYPE_PEER:
		return "PEER";
	case LSA_ATTR_TYPE_NODE_NAME:
		return "NODE_NAME";
	case LSA_ATTR_TYPE_VERSION:
		return "VERSION";
	case LSA_ATTR_TYPE_PUBKEY:
		return "PUBKEY";
	default:
		snprintf(buf, bufsize, "type-%d", type);
		return buf;
	}
}

void lsa_attr_print_type_name(FILE *fp, struct lsa_attr *attr)
{
	char t[128];

	fputs(lsa_attr_type_name(attr->type, t, sizeof(t)), fp);
}

static void print_node_name(FILE *fp, struct lsa_attr *attr)
{
	uint8_t *data = lsa_attr_data(attr);
	int i;

	for (i = 0; i < attr->datalen; i++) {
		if (isalnum(data[i]))
			fputc(data[i], fp);
		else
			fputc('_', fp);
	}
}

int lsa_print_id_name(FILE *fp, uint8_t *id, struct loc_rib *name_hints)
{
	if (name_hints != NULL) {
		struct loc_rib_id *rid;

		rid = loc_rib_find_id(name_hints, id);
		if (rid != NULL && rid->best != NULL) {
			struct lsa_attr *attr;

			attr = lsa_attr_find(rid->best,
					     LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
			if (attr != NULL) {
				print_node_name(fp, attr);
				return 1;
			}
		}
	}

	printhex(fp, id, NODE_ID_LEN);

	return 0;
}

void lsa_attr_print_key(FILE *fp, struct lsa_attr *attr,
			struct loc_rib *name_hints)
{
	fprintf(fp, "[");
	if (attr->type == LSA_ATTR_TYPE_PEER && attr->keylen == NODE_ID_LEN) {
		lsa_print_id_name(fp, lsa_attr_key(attr), name_hints);
	} else {
		printhex(fp, lsa_attr_key(attr), attr->keylen);
	}
	fprintf(fp, "]");
}

static int try_print_der_pubkey(FILE *fp, void *data, int len)
{
	gnutls_pubkey_t pubkey;
	int ret;
	gnutls_datum_t d;
	gnutls_datum_t n;
	gnutls_datum_t e;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0) {
		gnutls_perror(ret);
		return -1;
	}

	d.data = data;
	d.size = len;

	ret = gnutls_pubkey_import(pubkey, &d, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_perror(ret);
		gnutls_pubkey_deinit(pubkey);
		return -1;
	}

	ret = gnutls_pubkey_export_rsa_raw(pubkey, &n, &e);
	if (ret < 0) {
		gnutls_perror(ret);
		gnutls_pubkey_deinit(pubkey);
		return -1;
	}

	fprintf(fp, "n=");
	printhex(fp, n.data, n.size);
	fprintf(fp, " e=");
	printhex(fp, e.data, e.size);

	gnutls_free(n.data);
	gnutls_free(e.data);

	gnutls_pubkey_deinit(pubkey);

	return 0;
}

static void print_der_pubkey(FILE *fp, void *data, int len)
{
	if (try_print_der_pubkey(fp, data, len) < 0)
		printhex(fp, data, len);
}

void lsa_attr_print_data(FILE *fp, struct lsa_attr *attr,
			 struct loc_rib *name_hints)
{
	fprintf(fp, "[");
	if (attr->type == LSA_ATTR_TYPE_ADV_PATH &&
	    (attr->datalen % NODE_ID_LEN) == 0) {
		uint8_t *data = lsa_attr_data(attr);
		int i;

		for (i = 0; i < attr->datalen; i += NODE_ID_LEN) {
			if (i)
				fputc(' ', fp);
			lsa_print_id_name(fp, data + i, name_hints);
		}
	} else if (attr->type == LSA_ATTR_TYPE_PEER &&
		   attr->datalen == sizeof(struct lsa_attr_peer)) {
		struct lsa_attr_peer *peer = lsa_attr_data(attr);

		fprintf(fp, "metric=%d type=", ntohs(peer->metric));
		if (peer->peer_type == LSA_PEER_TYPE_EPEER)
			fprintf(fp, "epeer");
		else if (peer->peer_type == LSA_PEER_TYPE_CUSTOMER)
			fprintf(fp, "customer");
		else if (peer->peer_type == LSA_PEER_TYPE_TRANSIT)
			fprintf(fp, "transit");
		else if (peer->peer_type == LSA_PEER_TYPE_IPEER)
			fprintf(fp, "ipeer");
		else
			fprintf(fp, "%d", peer->peer_type);
	} else if (attr->type == LSA_ATTR_TYPE_NODE_NAME) {
		print_node_name(fp, attr);
	} else if (attr->type == LSA_ATTR_TYPE_VERSION) {
		printhex(fp, lsa_attr_data(attr), attr->datalen);
	} else if (attr->type == LSA_ATTR_TYPE_PUBKEY) {
		print_der_pubkey(fp, lsa_attr_data(attr), attr->datalen);
	} else {
		printhex(fp, lsa_attr_data(attr), attr->datalen);
	}
	fprintf(fp, "]");
}

void lsa_print(FILE *fp, struct lsa *lsa, struct loc_rib *name_hints)
{
	struct iv_avl_node *an;

	fprintf(fp, "LSA [");
	printhex(fp, lsa->id, NODE_ID_LEN / 2);
	fprintf(fp, ":\n     ");
	printhex(fp, lsa->id + (NODE_ID_LEN / 2), NODE_ID_LEN / 2);
	fprintf(fp, "]\n");

	iv_avl_tree_for_each (an, &lsa->attrs) {
		struct lsa_attr *attr;

		attr = iv_container_of(an, struct lsa_attr, an);

		fprintf(fp, "* ");
		lsa_attr_print_type_name(fp, attr);
		if (attr->keylen)
			lsa_attr_print_key(fp, attr, name_hints);
		fprintf(fp, " = ");
		lsa_attr_print_data(fp, attr, name_hints);
		fprintf(fp, "\n");
	}
}
