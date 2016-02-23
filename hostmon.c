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
#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <string.h>
#include "conf.h"
#include "dgp_connect.h"
#include "loc_rib.h"
#include "lsa.h"
#include "lsa_type.h"
#include "util.h"
#include "x509.h"

static uint8_t myid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct rib_listener rib_listener;
static struct dgp_connect dc;
static struct iv_signal sigint;

static void lsa_chg(char chg, struct lsa *a)
{
	struct lsa_attr *attr;
	uint8_t addr[16];
	char dst[128];
	uint8_t *data;
	int i;

	attr = lsa_find_attr(a, LSA_ATTR_TYPE_NODE_NAME, NULL, 0);
	if (attr == NULL)
		return;

	v6_global_addr_from_key_id(addr, a->id);
	printf("%c%s ", chg, inet_ntop(AF_INET6, addr, dst, sizeof(dst)));

	data = lsa_attr_data(attr);
	for (i = 0; i < attr->datalen; i++) {
		if (isalnum(data[i]))
			putchar(data[i]);
		else
			putchar('_');
	}

	printf("\n");
}

static void lsa_add(void *_dummy, struct lsa *a, uint32_t cost)
{
	lsa_chg('+', a);
}

static void lsa_mod(void *_dummy, struct lsa *a, uint32_t acost,
		    struct lsa *b, uint32_t bcost)
{
	lsa_chg('-', a);
	lsa_chg('+', b);
}

static void lsa_del(void *_dummy, struct lsa *a, uint32_t cost)
{
	lsa_chg('-', a);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	loc_rib_listener_unregister(&loc_rib, &rib_listener);
	dgp_connect_stop(&dc);

	iv_signal_unregister(&sigint);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
		{ 0, 0, 0, 0, },
	};
	const char *config = "/etc/dvpn.ini";
	struct conf *conf;
	gnutls_x509_privkey_t privkey;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "c:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config = optarg;
			break;

		case '?':
			fprintf(stderr, "syntax: %s [-c <config.ini>]\n",
				argv[0]);
			return 1;

		default:
			abort();
		}
	}

	conf = parse_config(config);
	if (conf == NULL)
		return 1;

	gnutls_global_init();

	if (x509_read_privkey(&privkey, conf->private_key) < 0)
		return 1;

	free_config(conf);

	x509_get_privkey_id(myid, privkey);

	gnutls_x509_privkey_deinit(privkey);

	gnutls_global_deinit();

	iv_init();

	loc_rib.myid = NULL;
	loc_rib_init(&loc_rib);

	rib_listener.lsa_add = lsa_add;
	rib_listener.lsa_mod = lsa_mod;
	rib_listener.lsa_del = lsa_del;
	loc_rib_listener_register(&loc_rib, &rib_listener);

	dc.myid = NULL;
	dc.remoteid = myid;
	dc.ifindex = 0;
	dc.loc_rib = &loc_rib;
	dgp_connect_start(&dc);

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	loc_rib_deinit(&loc_rib);

	iv_deinit();

	return 0;
}
