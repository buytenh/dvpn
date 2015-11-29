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
#include <gnutls/x509.h>
#include <stdint.h>
#include <unistd.h>
#include "x509.h"

int main(int argc, char *argv[])
{
	gnutls_x509_privkey_t key;
	uint8_t id[20];
	ssize_t len;
	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: %s [keyfile]\n", argv[0]);
		return 1;
	}

	gnutls_global_init();

	if (x509_read_privkey(&key, argv[1]) < 0)
		goto err;

	len = x509_get_key_id(id, sizeof(id), key);
	if (len != 20)
		goto err_deinit_priv;

	for (i = 0; i < 20; i++) {
		printf("%.2x", id[i]);
		if (i != 19)
			printf(":");
	}
	printf("\n");

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	return 0;

err_deinit_priv:
	gnutls_x509_privkey_deinit(key);

err:
	gnutls_global_deinit();

	return 1;
}
