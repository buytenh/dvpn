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

#ifndef __DGP_READER_H
#define __DGP_READER_H

#include <iv.h>
#include "adj_rib_in.h"
#include "loc_rib.h"
#include "rib_listener.h"
#include "rib_listener_to_loc.h"

struct dgp_reader {
	const uint8_t		*myid;
	const uint8_t		*remoteid;
	struct loc_rib		*rib;
	void			*cookie;
	void			(*io_error)(void *cookie);

	int				bytes;
	uint8_t				buf[65536];
	struct adj_rib_in		adj_rib_in;
	struct rib_listener_to_loc	to_loc;
	struct iv_timer			keepalive_timeout;
};

void dgp_reader_register(struct dgp_reader *dr);
int dgp_reader_read(struct dgp_reader *dr, int fd);
void dgp_reader_unregister(struct dgp_reader *dr);


#endif
