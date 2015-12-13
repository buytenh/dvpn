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

#ifndef __CONFDIFF_H
#define __CONFDIFF_H

#include "conf.h"

struct confdiff_request
{
	struct conf	*conf;
	struct conf	*newconf;
	int	(*new_connect_entry)(struct conf_connect_entry *);
	void	(*removed_connect_entry)(struct conf_connect_entry *);
	int	(*new_listening_socket)(struct conf_listening_socket *);
	void	(*removed_listening_socket)(struct conf_listening_socket *);
	int	(*new_listen_entry)(struct conf_listening_socket *,
				    struct conf_listen_entry *);
	void	(*removed_listen_entry)(struct conf_listening_socket *,
					struct conf_listen_entry *);
};

void diff_configs(struct confdiff_request *req);


#endif
