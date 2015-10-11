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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <iv.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "pconn.h"

static struct pconn sc;
static struct pconn cc;

static void server_handshake_done(void *cookie, const uint8_t *fp, int len)
{
	printf("server_handshake_done\n");
}

static void server_record_received(void *cookie, const uint8_t *rec, int len)
{
	printf("server_record_received\n");
}

static void server_connection_lost(void *ptr)
{
	printf("server_connection_lost\n");
}

static void client_handshake_done(void *cookie, const uint8_t *fp, int len)
{
	printf("client_handshake_done\n");
}

static void client_record_received(void *cookie, const uint8_t *rec, int len)
{
	printf("client_record_received\n");
}

static void client_connection_lost(void *ptr)
{
	printf("client_connection_lost\n");
}

int main(void)
{
	int fd[2];

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) < 0) {
		perror("socketpair");
		return 1;
	}

	printf("hi!\n");

	iv_init();

	sc.fd = fd[0];
	sc.role = PCONN_ROLE_SERVER;
	sc.cookie = &sc;
	sc.handshake_done = server_handshake_done;
	sc.record_received = server_record_received;
	sc.connection_lost = server_connection_lost;
	pconn_start(&sc);

	cc.fd = fd[1];
	cc.role = PCONN_ROLE_CLIENT;
	cc.cookie = &cc;
	cc.handshake_done = client_handshake_done;
	cc.record_received = client_record_received;
	cc.connection_lost = client_connection_lost;
	pconn_start(&cc);

	iv_main();

	return 0;
}
