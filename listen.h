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

#ifndef __LISTEN_H
#define __LISTEN_H

#include <gnutls/x509.h>
#include "conf.h"

void *listening_socket_add(struct conf_listening_socket *cls,
			   gnutls_x509_privkey_t key);
void *listening_socket_add_entry(void *ls, struct conf_listen_entry *cle);
void listening_socket_del_entry(void *ls, void *le);
void listening_socket_del(void *ls);


#endif
