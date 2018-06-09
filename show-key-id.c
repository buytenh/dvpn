/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015, 2016 Lennert Buytenhek
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
#include <fcntl.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util.h"
#include "x509.h"

static int try_privkey(uint8_t *id, uint8_t *buf, int size)
{
	gnutls_x509_privkey_t privkey;
	gnutls_datum_t datum;
	int ret;

	ret = gnutls_x509_privkey_init(&privkey);
	if (ret) {
		fprintf(stderr, "gnutls_x509_privkey_init: ");
		gnutls_perror(ret);
		return -1;
	}

	datum.data = buf;
	datum.size = size;

	ret = gnutls_x509_privkey_import(privkey, &datum, GNUTLS_X509_FMT_PEM);
	if (ret) {
		gnutls_x509_privkey_deinit(privkey);
		return -1;
	}

	ret = x509_get_privkey_id(id, privkey);

	gnutls_x509_privkey_deinit(privkey);

	return ret;
}

static int try_pubkey(uint8_t *id, uint8_t *buf, int size)
{
	gnutls_pubkey_t pubkey;
	gnutls_datum_t datum;
	int ret;

	ret = gnutls_pubkey_init(&pubkey);
	if (ret) {
		fprintf(stderr, "gnutls_pubkey_init: ");
		gnutls_perror(ret);
		return -1;
	}

	datum.data = buf;
	datum.size = size;

	ret = gnutls_pubkey_import(pubkey, &datum, GNUTLS_X509_FMT_PEM);
	if (ret) {
		gnutls_pubkey_deinit(pubkey);
		return -1;
	}

	ret = get_pubkey_id(id, pubkey);

	gnutls_pubkey_deinit(pubkey);

	return ret;
}

static int read_key_id(uint8_t *id, const char *file)
{
	int fd;
	uint8_t buf[65536];
	int size;
	int ret;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error opening %s: %s\n", file,
			strerror(errno));
		return -1;
	}

	size = read(fd, buf, sizeof(buf));
	if (size < 0) {
		perror("read_key_id: read");
		close(fd);
		return -1;
	}

	close(fd);

	gnutls_global_init();

	ret = try_privkey(id, buf, size);
	if (ret)
		ret = try_pubkey(id, buf, size);

	gnutls_global_deinit();

	return !!ret;
}

int show_key_id(const char *file)
{
	uint8_t keyid[NODE_ID_LEN];
	int ret;

	if (file == NULL) {
		fprintf(stderr, "usage: show-key-id <key.pem>\n");
		return 1;
	}

	ret = read_key_id(keyid, file);
	if (ret == 0) {
		print_fingerprint(stdout, keyid);
		printf("\n");
	}

	return ret;
}

int show_key_id_hex(const char *file)
{
	uint8_t keyid[NODE_ID_LEN];
	int ret;

	if (file == NULL) {
		fprintf(stderr, "usage: show-key-id-hex <key.pem>\n");
		return 1;
	}

	ret = read_key_id(keyid, file);
	if (ret == 0) {
		int i;

		for (i = 0; i < NODE_ID_LEN; i++) {
			printf("%.2x%c", keyid[i],
			       (i < NODE_ID_LEN - 1) ? ':' : '\n');
		}
	}

	return ret;
}
