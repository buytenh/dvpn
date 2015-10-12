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
	gnutls_x509_crt_t crt;
	uint8_t buf[4096];
	size_t size;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "usage: %s [keyfile]\n", argv[0]);
		return 1;
	}

	gnutls_global_init();

	if (x509_read_privkey(&key, argv[1]) < 0)
		goto err;

	if (x509_generate_cert(&crt, key) < 0)
		goto err_deinit_priv;

	size = sizeof(buf);

	ret = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, buf, &size);
	if (ret < 0) {
		gnutls_perror(ret);
		goto err_deinit_crt;
	}

	write(1, buf, size);

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	return 0;

err_deinit_crt:
	gnutls_x509_crt_deinit(crt);

err_deinit_priv:
	gnutls_x509_privkey_deinit(key);

err:
	gnutls_global_deinit();

	return 1;
}
