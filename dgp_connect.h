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

#ifndef __DGP_CONNECT_H
#define __DGP_CONNECT_H

#include <iv.h>
#include "loc_rib.h"
#include "dgp_reader.h"
#include "dgp_writer.h"

struct dgp_connect {
	uint8_t			*myid;
	uint8_t			*remoteid;
	int			ifindex;
	struct loc_rib		*loc_rib;

	int			state;
	struct iv_timer		timeout;
	struct iv_fd		fd;
	struct dgp_reader	dr;
	struct dgp_writer	dw;
};

void dgp_connect_start(struct dgp_connect *dc);
void dgp_connect_stop(struct dgp_connect *dc);


#endif
