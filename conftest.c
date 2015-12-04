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
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include "conf.h"
#include "util.h"

static void print_config(struct conf *conf)
{
	struct iv_list_head *lh;

	printf("private key: %s\n", conf->private_key ? : "(null)");

	iv_list_for_each (lh, &conf->connect_entries) {
		struct conf_connect_entry *cce;

		cce = iv_list_entry(lh, struct conf_connect_entry, list);

		printf("\n");
		printf("connect '%s'\n", cce->name);
		printf("- hostname: [%s]:%s\n", cce->hostname, cce->port);
		printf("- fp: ");
		printhex(stdout, cce->fingerprint, 20);
		printf("\n");
		printf("- is_peer: %d\n", cce->is_peer);
		printf("- tunitf: %s\n", cce->tunitf);
	}

	iv_list_for_each (lh, &conf->listening_sockets) {
		struct conf_listening_socket *cls;
		struct iv_list_head *lh2;

		cls = iv_list_entry(lh, struct conf_listening_socket, list);

		printf("\n");
		printf("listening socket\n");
		printf("- address: ");
		print_address(stdout, (struct sockaddr *)&cls->listen_address);
		printf("\n");

		iv_list_for_each (lh2, &cls->listen_entries) {
			struct conf_listen_entry *cle;

			cle = iv_list_entry(lh2, struct conf_listen_entry,
					    list);

			printf("- entry '%s'\n", cle->name);
			printf("  - fp: ");
			printhex(stdout, cle->fingerprint, 20);
			printf("\n");
			printf("  - is_peer: %d\n", cle->is_peer);
			printf("  - tunitf: %s\n", cle->tunitf);
		}
	}
}

int main(void)
{
	struct conf *conf;

	conf = parse_config("dvpn.ini");
	if (conf == NULL)
		return 1;

	print_config(conf);

	free_config(conf);

	return 0;
}
