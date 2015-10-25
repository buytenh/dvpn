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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <netdb.h>
#include <string.h>
#include "tun.h"
#include "pconn.h"
#include "x509.h"

#define STATE_HANDSHAKE		1
#define STATE_CONNECTED		2

static int serverport = 19275;
static const char *itfname;
static gnutls_x509_privkey_t key;

struct iv_fd listen_fd;
struct iv_signal sigint;

struct client
{
	int			state;
	struct pconn		conn;
	struct tun_interface	tun;
	// @@@ add keepalive timer
};

static void printhex(const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%.2x", a[i]);
		if (i < len - 1)
			fprintf(stderr, ":");
	}
}

static void client_kill(struct client *cl)
{
	pconn_destroy(&cl->conn);
	close(cl->conn.fd);

	if (cl->state == STATE_CONNECTED)
		tun_interface_unregister(&cl->tun);

	free(cl);
}

static int verify_key_id(void *_cl, const uint8_t *id, int len)
{
	fprintf(stderr, "key id: ");
	printhex(id, len);
	fprintf(stderr, "\n");

	return 0;
}

static void handshake_done(void *_cl)
{
	struct client *cl = _cl;

	fprintf(stderr, "%p: handshake done\n", cl);

	if (tun_interface_register(&cl->tun) < 0) {
		client_kill(cl);
		return;
	}

	cl->state = STATE_CONNECTED;
}

static void record_received(void *_cl, const uint8_t *rec, int len)
{
	struct client *cl = _cl;
	int rlen;

	fprintf(stderr, "%p: record received, len = %d\n", cl, len);

	if (len < 2)
		return;

	rlen = (rec[0] << 8) | rec[1];
	if (rlen != len + 2)
		return;

	if (tun_interface_send_packet(&cl->tun, rec + 2, rlen) < 0)
		client_kill(cl);
}

static void connection_lost(void *_cl)
{
	struct client *cl = _cl;

	fprintf(stderr, "%p: connection lost\n", cl);

	client_kill(cl);
}

static void got_packet(void *_cl, uint8_t *buf, int len)
{
	struct client *cl = _cl;
	uint8_t sndbuf[len + 2];

	fprintf(stderr, "%p: sending record, len = %d\n", cl, len + 2);

	sndbuf[0] = len >> 8;
	sndbuf[1] = len & 0xff;
	memcpy(sndbuf + 2, buf, len);

	if (pconn_record_send(&cl->conn, sndbuf, len + 2))
		client_kill(cl);
}

static void got_connection(void *_dummy)
{
	struct sockaddr_in addr;
	socklen_t addrlen;
	int fd;
	struct client *cl;

	addrlen = sizeof(addr);

	fd = accept(listen_fd.fd, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		perror("accept");
		return;
	}

	cl = malloc(sizeof(*cl));
	if (cl == NULL) {
		close(fd);
		return;
	}

	cl->state = STATE_HANDSHAKE;

	cl->conn.fd = fd;
	cl->conn.role = PCONN_ROLE_SERVER;
	cl->conn.key = key;
	cl->conn.cookie = cl;
	cl->conn.verify_key_id = verify_key_id;
	cl->conn.handshake_done = handshake_done;
	cl->conn.record_received = record_received;
	cl->conn.connection_lost = connection_lost;
	pconn_start(&cl->conn);

	cl->tun.itfname = itfname;
	cl->tun.cookie = cl;
	cl->tun.got_packet = got_packet;
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_fd_unregister(&listen_fd);
	close(listen_fd.fd);

	iv_signal_unregister(&sigint);
}

int main(void)
{
	int fd;
	struct sockaddr_in addr;
	int yes;

	gnutls_global_init();

	iv_init();

	serverport = 19275;
	itfname = "tap%d";
	if (x509_read_privkey(&key, "server.key") < 0)
		return 1;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(serverport);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("setsockopt");
		return 1;
	}

	if (listen(fd, 100) < 0) {
		perror("listen");
		return 1;
	}

	IV_FD_INIT(&listen_fd);
	listen_fd.fd = fd;
	listen_fd.handler_in = got_connection;
	iv_fd_register(&listen_fd);

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	iv_deinit();

	gnutls_x509_privkey_deinit(key);

	gnutls_global_deinit();

	return 0;
}
