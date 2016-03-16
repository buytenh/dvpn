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

#ifndef __DGP_WRITER_H
#define __DGP_WRITER_H

#include <iv.h>
#include "loc_rib.h"
#include "rib_listener.h"

struct dgp_writer {
	int			fd;
	const uint8_t		*myid;
	const uint8_t		*remoteid;
	struct loc_rib		*rib;
	void			*cookie;
	void			(*io_error)(void *cookie);

	struct rib_listener	from_loc;
	struct iv_timer		keepalive_timer;
};

void dgp_writer_register(struct dgp_writer *dw);
void dgp_writer_unregister(struct dgp_writer *dw);


#endif
