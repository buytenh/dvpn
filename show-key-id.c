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
#include <gnutls/x509.h>
#include "util.h"
#include "x509.h"

int show_key_id(const char *file)
{
	gnutls_x509_privkey_t privkey;
	int ret;
	uint8_t keyid[NODE_ID_LEN];

	if (file == NULL) {
		fprintf(stderr, "syntax: show-key-id <key.pem>\n");
		return 1;
	}

	gnutls_global_init();

	ret = x509_read_privkey(&privkey, file);
	if (ret == 0) {
		ret = x509_get_privkey_id(keyid, privkey);
		if (ret == 0) {
			print_fingerprint(stdout, keyid);
			printf("\n");
		}
		gnutls_x509_privkey_deinit(privkey);
	}

	gnutls_global_deinit();

	return !!ret;
}
