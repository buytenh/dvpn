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
#include <arpa/inet.h>
#include <stdint.h>
#include "lsa.h"
#include "lsa_peer.h"
#include "lsa_type.h"

int lsa_get_peer_info(struct lsa_peer_info *lpi, struct lsa *lsa,
		      const uint8_t *peerid)
{
	struct lsa_attr *peer;
	struct lsa_attr_set *set;
	struct lsa_attr *attr;

	peer = lsa_find_attr(lsa, LSA_ATTR_TYPE_PEER, peerid, NODE_ID_LEN);
	if (peer == NULL || !peer->attr_signed || !peer->data_is_attr_set)
		return -1;

	set = lsa_attr_data(peer);

	attr = lsa_attr_set_find_attr(set, LSA_PEER_ATTR_TYPE_METRIC, NULL, 0);
	if (attr != NULL && attr->attr_signed && attr->datalen == 2)
		lpi->metric = ntohs(*((uint16_t *)lsa_attr_data(attr)));
	else
		lpi->metric = 1;

	attr = lsa_attr_set_find_attr(set, LSA_PEER_ATTR_TYPE_PEER_FLAGS,
				      NULL, 0);
	if (attr != NULL && attr->attr_signed && attr->datalen == 1)
		lpi->flags = *((uint8_t *)lsa_attr_data(attr));
	else
		lpi->flags = 0;

	return 0;
}
