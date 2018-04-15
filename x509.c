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
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <nettle/sha2.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "util.h"
#include "x509.h"

int x509_read_privkey(gnutls_x509_privkey_t *privkey, const char *file,
		      int ignore_open_error)
{
	int fd;
	uint8_t buf[65536];
	int size;
	int ret;
	gnutls_datum_t datum;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		if (ignore_open_error) {
			*privkey = NULL;
			return 0;
		}

		fprintf(stderr, "error opening %s: %s\n", file,
			strerror(errno));
		return -1;
	}

	size = read(fd, buf, sizeof(buf));
	if (size < 0) {
		perror("x509_read_privkey: read");
		close(fd);
		return -1;
	}

	close(fd);

	ret = gnutls_x509_privkey_init(privkey);
	if (ret) {
		fprintf(stderr, "x509_read_privkey: ");
		gnutls_perror(ret);
		return -1;
	}

	datum.data = buf;
	datum.size = size;

	ret = gnutls_x509_privkey_import(*privkey, &datum, GNUTLS_X509_FMT_PEM);
	if (ret) {
		fprintf(stderr, "x509_read_privkey: ");
		gnutls_perror(ret);
		gnutls_x509_privkey_deinit(*privkey);
		return -1;
	}

	return 0;
}

int x509_privkey_to_der_pubkey(uint8_t *buf, int buflen,
                               gnutls_x509_privkey_t x509_privkey)
{
	gnutls_privkey_t privkey;
	int ret;
	gnutls_pubkey_t pubkey;
	size_t len;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0)
		goto err;

	ret = gnutls_privkey_import_x509(privkey, x509_privkey, 0);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	if (ret < 0)
		goto err_free_pub;

	len = buflen;

	ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, buf, &len);
	if (ret < 0)
		goto err_free_pub;

	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);

	return len;

err_free_pub:
	gnutls_pubkey_deinit(pubkey);

err_free_priv:
	gnutls_privkey_deinit(privkey);

err:
	fprintf(stderr, "x509_privkey_to_der_pubkey: ");
	gnutls_perror(ret);

	return -1;
}

int get_pubkey_id(uint8_t *id, gnutls_pubkey_t pubkey)
{
	uint8_t buf[65536];
	size_t len;
	int ret;
	struct sha256_ctx ctx;

	len = sizeof(buf);

	ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, buf, &len);
	if (ret < 0)
		return ret;

	sha256_init(&ctx);
	sha256_update(&ctx, len, buf);
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, id);

	return 0;
}

int x509_get_privkey_id(uint8_t *id, gnutls_x509_privkey_t x509_privkey)
{
	gnutls_privkey_t privkey;
	int ret;
	gnutls_pubkey_t pubkey;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0)
		goto err;

	ret = gnutls_privkey_import_x509(privkey, x509_privkey, 0);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	if (ret < 0)
		goto err_free_pub;

	ret = get_pubkey_id(id, pubkey);
	if (ret < 0)
		goto err_free_pub;

	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);

	return 0;

err_free_pub:
	gnutls_pubkey_deinit(pubkey);

err_free_priv:
	gnutls_privkey_deinit(privkey);

err:
	fprintf(stderr, "x509_get_privkey_id: ");
	gnutls_perror(ret);

	return -1;
}

static int __x509_generate_self_signed_cert(gnutls_x509_crt_t *_crt,
					    gnutls_x509_privkey_t x509_privkey,
					    const char *dn)
{
	gnutls_privkey_t privkey;
	int ret;
	gnutls_x509_crt_t crt;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0)
		goto err;

	ret = gnutls_privkey_import_x509(privkey, x509_privkey, 0);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_x509_crt_set_serial(crt, "\x01", 1);
	if (ret < 0)
		goto err_free_crt;

	if (dn != NULL) {
		ret = gnutls_x509_crt_set_dn(crt, dn, NULL);
		if (ret < 0)
			goto err_free_crt;
	}

	ret = gnutls_x509_crt_set_activation_time(crt, 0);
	if (ret < 0)
		goto err_free_crt;

	ret = gnutls_x509_crt_set_expiration_time(crt,
			GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION);
	if (ret < 0)
		goto err_free_crt;

	ret = gnutls_x509_crt_set_key(crt, x509_privkey);
	if (ret < 0)
		goto err_free_crt;

	ret = gnutls_x509_crt_privkey_sign(crt, crt, privkey,
					   GNUTLS_DIG_SHA256, 0);
	if (ret < 0)
		goto err_free_crt;

	gnutls_privkey_deinit(privkey);

	*_crt = crt;

	return 0;

err_free_crt:
	gnutls_x509_crt_deinit(crt);

err_free_priv:
	gnutls_privkey_deinit(privkey);

err:
	return ret;
}

int x509_generate_role_cert(gnutls_x509_crt_t *crt,
			    gnutls_x509_privkey_t node_key,
			    gnutls_x509_privkey_t role_key)
{
	uint8_t node_id[NODE_ID_LEN];
	int ret;
	char dn[128];
	int i;

	ret = x509_get_privkey_id(node_id, node_key);
	if (ret < 0)
		goto err;

	sprintf(dn, "CN=");
	for (i = 0; i < NODE_ID_LEN; i++)
		sprintf(dn + 3 + (2 * i), "%.2x", node_id[i]);
	dn[67] = 0;

	ret = __x509_generate_self_signed_cert(crt, role_key, dn);
	if (ret < 0)
		goto err;

	return 0;

err:
	fprintf(stderr, "x509_generate_role_cert: ");
	gnutls_perror(ret);

	return -1;
}

int x509_generate_self_signed_cert(gnutls_x509_crt_t *crt,
				   gnutls_x509_privkey_t x509_privkey)
{
	int ret;

	ret = __x509_generate_self_signed_cert(crt, x509_privkey, NULL);
	if (ret < 0) {
		fprintf(stderr, "x509_generate_self_signed_cert: ");
		gnutls_perror(ret);
	}

	return ret;
}
