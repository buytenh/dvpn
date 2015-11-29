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
	int bits;
	gnutls_x509_privkey_t key;
	int ret;
	int fd;
	uint8_t buf[8192];
	size_t size;
	ssize_t len;

	if (argc < 3 || sscanf(argv[2], "%d", &bits) != 1) {
		fprintf(stderr, "usage: %s [keyfile] [bits]\n", argv[0]);
		return 1;
	}

	gnutls_global_init();

	ret = gnutls_x509_privkey_init(&key);
	if (ret) {
		gnutls_perror(ret);
		return 1;
	}

	ret = gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, bits, 0);
	if (ret < 0) {
		gnutls_perror(ret);
		return 1;
	}

	size = sizeof(buf);

	ret = gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM, buf, &size);
	if (ret < 0) {
		gnutls_perror(ret);
		return 1;
	}

	fd = open(argv[1], O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	write(fd, buf, size);
	close(fd);

	len = x509_get_key_id(buf, sizeof(buf), key);
	if (len == 20) {
		int i;

		for (i = 0; i < 20; i++) {
			printf("%.2x", buf[i]);
			if (i != 19)
				printf(":");
		}
		printf("\n");
	}

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	return 0;
}
