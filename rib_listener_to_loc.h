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

#ifndef __RIB_LISTENER_TO_LOC_H
#define __RIB_LISTENER_TO_LOC_H

#include "rib_listener.h"

struct rib_listener_to_loc {
	struct loc_rib		*dest;
	struct rib_listener	rl;
};

void rib_listener_to_loc_init(struct rib_listener_to_loc *rl);
void rib_listener_to_loc_deinit(struct rib_listener_to_loc *rl);


#endif
