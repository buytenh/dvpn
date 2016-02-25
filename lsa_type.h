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
	LSA_ATTR_TYPE_VERSION = 4,
	LSA_ATTR_TYPE_PUBKEY = 5,
};

enum lsa_attr_flags {
	LSA_ATTR_FLAG_HAS_KEY = 1,
	LSA_ATTR_FLAG_DATA_IS_TLV = 2,
};

enum lsa_peer_attr_type {
	LSA_PEER_ATTR_TYPE_METRIC = 1,
	LSA_PEER_ATTR_TYPE_PEER_FLAGS = 2,
};

enum lsa_peer_type {
	LSA_PEER_FLAGS_CUSTOMER = 1,
	LSA_PEER_FLAGS_TRANSIT = 2,
};


#endif
