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
#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <iv.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "pconn.h"
#include "x509.h"

static int tcp_socketpair(int *fd)
{
	struct sockaddr_in addr;
	int lfd;
	int cfd;
	socklen_t addrlen;
	int sfd;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000002);
	addr.sin_port = htons(random() | 32768 | 16384);

	lfd = socket(PF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket");
		goto out;
	}

	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		goto free_lfd;
	}

	if (listen(lfd, 1) < 0) {
		perror("listen");
		goto free_lfd;
	}

	cfd = socket(PF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		perror("socket");
		goto free_lfd;
	}

	if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		goto free_cfd;
	}

	addrlen = sizeof(addr);

	sfd = accept(lfd, (struct sockaddr *)&addr, &addrlen);
	if (sfd < 0) {
		perror("accept");
		goto free_cfd;
	}

	close(lfd);

	fd[0] = sfd;
	fd[1] = cfd;

	return 0;

free_cfd:
	close(cfd);

free_lfd:
	close(lfd);

out:
	return -1;
}

static gnutls_x509_privkey_t skey;
static struct pconn sc;
static gnutls_x509_privkey_t ckey;
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

	srandom(time(NULL) ^ getpid());

	if (tcp_socketpair(fd) < 0) {
		perror("socketpair");
		return 1;
	}

	printf("hi!\n");

	iv_init();

	gnutls_global_init();

	if (x509_read_privkey(&skey, "server.key") < 0)
		return 1;

	sc.fd = fd[0];
	sc.role = PCONN_ROLE_SERVER;
	sc.key = skey;
	sc.cookie = &sc;
	sc.handshake_done = server_handshake_done;
	sc.record_received = server_record_received;
	sc.connection_lost = server_connection_lost;
	pconn_start(&sc);

	if (x509_read_privkey(&ckey, "client.key") < 0)
		return 1;

	cc.fd = fd[1];
	cc.role = PCONN_ROLE_CLIENT;
	cc.key = ckey;
	cc.cookie = &cc;
	cc.handshake_done = client_handshake_done;
	cc.record_received = client_record_received;
	cc.connection_lost = client_connection_lost;
	pconn_start(&cc);

	iv_main();

	gnutls_global_deinit();

	return 0;
}
