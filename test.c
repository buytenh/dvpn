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
#include <gnutls/x509.h>
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
		goto err;
	}

	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		goto err_free_lfd;
	}

	if (listen(lfd, 1) < 0) {
		perror("listen");
		goto err_free_lfd;
	}

	cfd = socket(PF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		perror("socket");
		goto err_free_lfd;
	}

	if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		goto err_free_cfd;
	}

	addrlen = sizeof(addr);

	sfd = accept(lfd, (struct sockaddr *)&addr, &addrlen);
	if (sfd < 0) {
		perror("accept");
		goto err_free_cfd;
	}

	close(lfd);

	fd[0] = sfd;
	fd[1] = cfd;

	return 0;

err_free_cfd:
	close(cfd);

err_free_lfd:
	close(lfd);

err:
	return -1;
}

static void printhex(const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%.2x", a[i]);
		if (i < len - 1)
			fprintf(stderr, ":");
	}
}

static gnutls_x509_privkey_t skey;
static struct pconn sc;
static gnutls_x509_privkey_t ckey;
static struct pconn cc;
static struct iv_timer tim;
static int connsend;

static int server_verify_key_id(void *cookie, const uint8_t *id, int len)
{
	fprintf(stderr, "server_verify_key_id: ");
	printhex(id, len);
	fprintf(stderr, "\n");

	return 0;
}

static void server_handshake_done(void *cookie)
{
	fprintf(stderr, "server_handshake_done\n");
}

static void server_record_received(void *cookie, const uint8_t *rec, int len)
{
	fprintf(stderr, "server_record_received: [");
	write(2, rec, len);
	fprintf(stderr, "]\n");
}

static void server_connection_lost(void *ptr)
{
	fprintf(stderr, "server_connection_lost\n");
}

static int client_verify_key_id(void *cookie, const uint8_t *id, int len)
{
	fprintf(stderr, "client_verify_key_id: ");
	printhex(id, len);
	fprintf(stderr, "\n");

	return 0;
}

static void client_handshake_done(void *cookie)
{
	fprintf(stderr, "client_handshake_done\n");
}

static void client_record_received(void *cookie, const uint8_t *rec, int len)
{
	fprintf(stderr, "client_record_received: [");
	write(2, rec, len);
	fprintf(stderr, "]\n");
}

static void client_connection_lost(void *ptr)
{
	fprintf(stderr, "client_connection_lost\n");
}

static void send_timer(void *_dummy)
{
	if (connsend == 250) {
		pconn_destroy(&sc);
		pconn_destroy(&cc);
		return;
	}

	if (connsend & 1) {
		if (cc.state == 2)
			pconn_record_send(&cc, (void *)"hello, server", 13);
	} else {
		if (sc.state == 2)
			pconn_record_send(&sc, (void *)"hello, client", 13);
	}

	connsend++;

	iv_validate_now();
	tim.expires = iv_now;
	tim.expires.tv_nsec += 10000000;
	if (tim.expires.tv_nsec >= 1000000000) {
		tim.expires.tv_sec++;
		tim.expires.tv_nsec -= 1000000000;
	}
	iv_timer_register(&tim);
}

int main(void)
{
	int fd[2];

	srandom(time(NULL) ^ getpid());

	if (tcp_socketpair(fd) < 0) {
		perror("socketpair");
		return 1;
	}

	fprintf(stderr, "hi!\n");

	iv_init();

	gnutls_global_init();

	if (x509_read_privkey(&skey, "server.key") < 0)
		return 1;

	sc.fd = fd[0];
	sc.role = PCONN_ROLE_SERVER;
	sc.key = skey;
	sc.cookie = &sc;
	sc.verify_key_id = server_verify_key_id;
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
	cc.verify_key_id = client_verify_key_id;
	cc.handshake_done = client_handshake_done;
	cc.record_received = client_record_received;
	cc.connection_lost = client_connection_lost;
	pconn_start(&cc);

	IV_TIMER_INIT(&tim);
	iv_validate_now();
	tim.expires = iv_now;
	tim.cookie = NULL;
	tim.handler = send_timer;
	iv_timer_register(&tim);

	iv_main();

	iv_deinit();

	gnutls_x509_privkey_deinit(skey);
	gnutls_x509_privkey_deinit(ckey);

	gnutls_global_deinit();

	return 0;
}
