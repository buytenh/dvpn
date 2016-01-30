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

static int dgp_reader_have_adj_rib_in(struct dgp_reader *dr)
{
	return (dr->myid != NULL && dr->remoteid != NULL);
}

void dgp_reader_register(struct dgp_reader *dr)
{
	dr->bytes = 0;

	if (dgp_reader_have_adj_rib_in(dr)) {
		dr->adj_rib_in.myid = dr->myid;
		dr->adj_rib_in.remoteid = dr->remoteid;
		adj_rib_in_init(&dr->adj_rib_in);

		dr->to_loc.dest = dr->rib;
		rib_listener_to_loc_init(&dr->to_loc);

		adj_rib_in_listener_register(&dr->adj_rib_in, &dr->to_loc.rl);
	}
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

	while (dr->bytes >= 2) {
		int len;

		len = ((dr->buf[0] << 8) | dr->buf[1]) + 2;
		if (dr->bytes < len)
			break;

		if (len >= 2 + NODE_ID_LEN) {
			struct lsa *lsa;

			lsa = lsa_deserialise(dr->buf, len);
			if (lsa == NULL)
				return -1;

			if (dgp_reader_have_adj_rib_in(dr))
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
	if (dgp_reader_have_adj_rib_in(dr)) {
		adj_rib_in_flush(&dr->adj_rib_in);
		rib_listener_to_loc_deinit(&dr->to_loc);
	}
}
