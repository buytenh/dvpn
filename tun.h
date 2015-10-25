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

#ifndef __TUN_H
#define __TUN_H

#include <iv.h>
#include <linux/if.h>

struct tun_interface {
	const char	*itfname;
	void		*cookie;
	void		(*got_packet)(void *cookie, uint8_t *buf, int len);

	char		name[IFNAMSIZ];
	struct iv_fd	fd;
};

int tun_interface_register(struct tun_interface *ti);
void tun_interface_unregister(struct tun_interface *ti);
char *tun_interface_get_name(struct tun_interface *ti);
int tun_interface_send_packet(struct tun_interface *ti,
			      const uint8_t *buf, int len);


#endif
