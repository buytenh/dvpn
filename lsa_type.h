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

#ifndef __LSA_TYPE_H
#define __LSA_TYPE_H

enum lsa_attr_type {
	LSA_ATTR_TYPE_ADV_PATH = 1,
	LSA_ATTR_TYPE_PEER = 2,
	LSA_ATTR_TYPE_NODE_NAME = 3,
};

struct lsa_attr_adv_path {
	uint8_t			node[0][32];
};

struct lsa_attr_peer {
	uint16_t		metric;
	uint8_t			peer_type;
} __attribute__((packed));

enum lsa_peer_type {
	LSA_PEER_TYPE_EPEER = 0,
	LSA_PEER_TYPE_CUSTOMER = 1,
	LSA_PEER_TYPE_TRANSIT = 2,
	LSA_PEER_TYPE_IPEER = 3,
};


#endif
