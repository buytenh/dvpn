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
#include <iv.h>
#include <string.h>
#include "dgp_reader.h"
#include "lsa_deserialise.h"

#define KEEPALIVE_TIMEOUT	15

static void dgp_reader_keepalive_timeout(void *_dr)
{
	struct dgp_reader *dr = _dr;

	dr->io_error(dr->cookie);
}

void dgp_reader_register(struct dgp_reader *dr)
{
	dr->bytes = 0;

	if (dr->remoteid != NULL) {
		dr->adj_rib_in.myid = dr->myid;
		dr->adj_rib_in.remoteid = dr->remoteid;
		adj_rib_in_init(&dr->adj_rib_in);

		dr->to_loc.dest = dr->rib;
		rib_listener_to_loc_init(&dr->to_loc);

		adj_rib_in_listener_register(&dr->adj_rib_in, &dr->to_loc.rl);
	}

	IV_TIMER_INIT(&dr->keepalive_timeout);
	iv_validate_now();
	dr->keepalive_timeout.expires = iv_now;
	dr->keepalive_timeout.expires.tv_sec += KEEPALIVE_TIMEOUT;
	dr->keepalive_timeout.cookie = dr;
	dr->keepalive_timeout.handler = dgp_reader_keepalive_timeout;
	iv_timer_register(&dr->keepalive_timeout);
}

int dgp_reader_read(struct dgp_reader *dr, int fd)
{
	int ret;

	do {
		ret = read(fd, dr->buf + dr->bytes, LSA_MAX_SIZE - dr->bytes);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EAGAIN)
				return 0;
			perror("dgp_reader_read");
		}
		return -1;
	}

	dr->bytes += ret;

	iv_timer_unregister(&dr->keepalive_timeout);
	iv_validate_now();
	dr->keepalive_timeout.expires = iv_now;
	dr->keepalive_timeout.expires.tv_sec += KEEPALIVE_TIMEOUT;
	iv_timer_register(&dr->keepalive_timeout);

	while (dr->bytes) {
		int len;
		struct lsa *lsa;

		len = lsa_deserialise(&lsa, dr->buf, dr->bytes);
		if (len < 0)
			return -1;

		if (len == 0)
			break;

		if (lsa != NULL) {
			if (dr->remoteid != NULL)
				adj_rib_in_add_lsa(&dr->adj_rib_in, lsa);

			lsa_put(lsa);
		}

		dr->bytes -= len;
		memmove(dr->buf, dr->buf + len, dr->bytes);
	}

	return 0;
}

void dgp_reader_unregister(struct dgp_reader *dr)
{
	if (dr->remoteid != NULL) {
		adj_rib_in_flush(&dr->adj_rib_in);
		rib_listener_to_loc_deinit(&dr->to_loc);
	}

	if (iv_timer_registered(&dr->keepalive_timeout))
		iv_timer_unregister(&dr->keepalive_timeout);
}
