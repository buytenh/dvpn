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
#include <gnutls/x509.h>
#include "util.h"
#include "x509.h"

static int read_key_id(uint8_t *id, const char *file)
{
	gnutls_x509_privkey_t privkey;
	int ret;

	gnutls_global_init();

	ret = x509_read_privkey(&privkey, file, 0);
	if (ret == 0) {
		ret = x509_get_privkey_id(id, privkey);
		gnutls_x509_privkey_deinit(privkey);
	}

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
