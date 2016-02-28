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
#include <getopt.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <string.h>
#include "conf.h"
#include "dgp_connect.h"
#include "loc_rib.h"
#include "loc_rib_print.h"
#include "rib_listener_debug.h"
#include "x509.h"

static uint8_t myid[NODE_ID_LEN];
static struct loc_rib loc_rib;
static struct rib_listener_debug debug_listener;
static struct dgp_connect dc;
static struct iv_signal sigint;
static struct iv_signal sigusr1;

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	loc_rib_listener_unregister(&loc_rib, &debug_listener.rl);
	dgp_connect_stop(&dc);

	iv_signal_unregister(&sigint);
	iv_signal_unregister(&sigusr1);
}

static void got_sigusr1(void *_dummy)
{
	loc_rib_print(stderr, &loc_rib);
}

int topomon_main(int argc, char *argv[])
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

	debug_listener.name = NULL;
	debug_listener.name_hints = &loc_rib;
	rib_listener_debug_init(&debug_listener);

	loc_rib_listener_register(&loc_rib, &debug_listener.rl);

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

	IV_SIGNAL_INIT(&sigusr1);
	sigusr1.signum = SIGUSR1;
	sigusr1.flags = 0;
	sigusr1.cookie = NULL;
	sigusr1.handler = got_sigusr1;
	iv_signal_register(&sigusr1);

	iv_main();

	loc_rib_deinit(&loc_rib);

	rib_listener_debug_deinit(&debug_listener);

	iv_deinit();

	return 0;
}
