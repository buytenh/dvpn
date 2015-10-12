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
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <stdint.h>
#include <unistd.h>
#include "x509.h"

int x509_read_privkey(gnutls_x509_privkey_t *key, const char *file)
{
	int fd;
	uint8_t buf[8192];
	int size;
	int ret;
	gnutls_datum_t datum;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	size = read(fd, buf, sizeof(buf));
	if (size < 0) {
		perror("read");
		close(fd);
		return -1;
	}

	close(fd);

	ret = gnutls_x509_privkey_init(key);
	if (ret) {
		gnutls_perror(ret);
		return -1;
	}

	datum.data = buf;
	datum.size = size;

	ret = gnutls_x509_privkey_import(*key, &datum, GNUTLS_X509_FMT_PEM);
	if (ret) {
		gnutls_perror(ret);
		gnutls_x509_privkey_deinit(*key);
		return -1;
	}

	return 0;
}

int x509_generate_cert(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t key)
{
	int ret;
	gnutls_privkey_t privkey;
	gnutls_pubkey_t pubkey;
	time_t now;
	uint8_t serial[5];
	uint8_t buf[256];
	size_t size;
	gnutls_digest_algorithm_t dig;

	ret = gnutls_x509_crt_init(crt);
	if (ret < 0)
		goto err;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0)
		goto err_free_crt;

	ret = gnutls_privkey_import_x509(privkey, key, 0);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0)
		goto err_free_priv;

	ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_pubkey(*crt, pubkey);
	if (ret < 0)
		goto err_free_pub;

	time(&now);

	ret = gnutls_x509_crt_set_activation_time(*crt, now);
	if (ret < 0)
		goto err_free_pub;

	serial[0] = (now >> 32) & 0xff;
	serial[1] = (now >> 24) & 0xff;
	serial[2] = (now >> 16) & 0xff;
	serial[3] = (now >> 8) & 0xff;
	serial[4] = now & 0xff;

	ret = gnutls_x509_crt_set_serial(*crt, serial, 5);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_expiration_time(*crt, now + 86400);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_basic_constraints(*crt, 0, -1);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_key_usage(*crt, GNUTLS_KEY_KEY_ENCIPHERMENT);
	if (ret < 0)
		goto err_free_pub;

	size = sizeof(buf);
	ret = gnutls_x509_crt_get_key_id(*crt, 0, buf, &size);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_subject_key_id(*crt, buf, size);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_set_version(*crt, 3);
	if (ret < 0)
		goto err_free_pub;

	/*
	 * @@@ FIXME: this leaks memory on gnutls 3.3.18 (8 bytes
	 * per call on x86_64).
	 */
	ret = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig, NULL);
	if (ret < 0)
		goto err_free_pub;

	ret = gnutls_x509_crt_privkey_sign(*crt, *crt, privkey, dig, 0);
	if (ret < 0)
		goto err_free_pub;

	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);

	return 0;

err_free_pub:
	gnutls_pubkey_deinit(pubkey);

err_free_priv:
	gnutls_privkey_deinit(privkey);

err_free_crt:
	gnutls_x509_crt_deinit(*crt);

err:
	gnutls_perror(ret);

	return -1;
}
