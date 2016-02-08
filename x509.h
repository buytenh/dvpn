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

#ifndef __X509_H
#define __X509_H

#include <gnutls/gnutls.h>

int x509_read_privkey(gnutls_x509_privkey_t *privkey, const char *file);
int get_sha256_pubkey_id(uint8_t *id, gnutls_pubkey_t pubkey);
int x509_get_privkey_id(uint8_t *id, gnutls_x509_privkey_t privkey);
int x509_generate_cert(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t privkey);


#endif
