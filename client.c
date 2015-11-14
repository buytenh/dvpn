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

/*
 * TODO:
 * - retry connections to other address families
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <iv_signal.h>
#include <netdb.h>
#include <string.h>
#include "iv_getaddrinfo.h"
#include "tun.h"
#include "pconn.h"
#include "x509.h"

#define STATE_RESOLVE		1
#define STATE_CONNECT		2
#define STATE_TLS_HANDSHAKE	3
#define STATE_CONNECTED		4
#define STATE_WAITING_RETRY	5

#define RESOLVE_TIMEOUT		10
#define CONNECT_TIMEOUT		10
#define HANDSHAKE_TIMEOUT	10
#define KEEPALIVE_INTERVAL	30
#define RETRY_WAIT_TIME		10

static const char *server;
static const char *serverport = "19275";
static const char *itf;
static gnutls_x509_privkey_t key;

static int state;
static struct addrinfo hints;
static struct iv_getaddrinfo addrinfo;
static struct iv_fd connectfd;
static struct tun_interface tun;
static struct pconn conn;
static struct iv_timer rx_timeout;
static struct iv_timer keepalive_timer;

static struct iv_signal sigint;

static void connect_done(void *cookie);

static void resolve_complete(void *cookie, int rc, struct addrinfo *res)
{
	struct addrinfo *rp;
	int fd;
	int ret;

	fprintf(stderr, "resolve_complete\n");
	if (rc) {
		fprintf(stderr, "resolving: %s\n", gai_strerror(rc));
		goto err;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;

		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

		ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
		if (ret < 0 && errno != EINPROGRESS) {
			close(fd);
			continue;
		}

		break;
	}

	if (rp == NULL) {
		fprintf(stderr, "error connecting\n");
		goto err;
	}

	freeaddrinfo(res);

	state = STATE_CONNECT;
	connectfd.fd = fd;

	if (ret == 0) {
		connect_done(NULL);
	} else {
		iv_fd_register(&connectfd);

		iv_validate_now();

		iv_timer_unregister(&rx_timeout);
		rx_timeout.expires = iv_now;
		rx_timeout.expires.tv_sec += CONNECT_TIMEOUT;
		iv_timer_register(&rx_timeout);
	}

	return;

err:
	if (res != NULL)
		freeaddrinfo(res);

	fprintf(stderr, "retrying in %d seconds\n", RETRY_WAIT_TIME);

	state = STATE_WAITING_RETRY;

	iv_validate_now();

	iv_timer_unregister(&rx_timeout);
	rx_timeout.expires = iv_now;
	rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	iv_timer_register(&rx_timeout);
}

static void connect_done(void *cookie)
{
	socklen_t len;
	int ret;

	len = sizeof(ret);
	if (getsockopt(connectfd.fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		perror("connect_done,getsockopt(SO_ERROR)");
		return;
	}

	if (ret == EINPROGRESS)
		return;

	if (iv_fd_registered(&connectfd))
		iv_fd_unregister(&connectfd);

	if (iv_timer_registered(&rx_timeout))
		iv_timer_unregister(&rx_timeout);

	iv_validate_now();

	rx_timeout.expires = iv_now;

	if (ret) {
		fprintf(stderr, "connect: %s\n", strerror(ret));
		close(connectfd.fd);

		fprintf(stderr, "retrying in %d seconds\n", RETRY_WAIT_TIME);

		state = STATE_WAITING_RETRY;

		rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	} else {
		state = STATE_TLS_HANDSHAKE;

		conn.fd = connectfd.fd;
		pconn_start(&conn);

		rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;
	}

	iv_timer_register(&rx_timeout);
}

static void got_packet(void *cookie, uint8_t *buf, int len)
{
	fprintf(stderr, "got_packet\n");
}

static void printhex(const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		printf("%.2x", a[i]);
		if (i < len - 1)
			printf(":");
	}
}

static int verify_key_id(void *cookie, const uint8_t *id, int len)
{
	printf("key id: ");
	printhex(id, len);
	printf("\n");

	return 0;
}

static void handshake_done(void *cookie)
{
	fprintf(stderr, "handshake_done\n");
}

static void record_received(void *cookie, const uint8_t *rec, int len)
{
	fprintf(stderr, "record_received\n");
}

static void connection_lost(void *ptr)
{
	fprintf(stderr, "connection_lost\n");
}

static void rx_timeout_expired(void *cookie)
{
	iv_validate_now();

	rx_timeout.expires = iv_now;

	if (state == STATE_WAITING_RETRY) {
		if (iv_getaddrinfo_submit(&addrinfo) < 0) {
			rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		} else {
			state = STATE_RESOLVE;
			rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
		}
	} else {
		if (state == STATE_RESOLVE) {
			iv_getaddrinfo_cancel(&addrinfo);
		} else if (state == STATE_CONNECT) {
			iv_fd_unregister(&connectfd);
			close(connectfd.fd);
		} else if (state == STATE_TLS_HANDSHAKE) {
			pconn_destroy(&conn);
			close(conn.fd);
		} else if (state == STATE_CONNECTED) {
			pconn_destroy(&conn);
			close(conn.fd);
		} else {
			abort();
		}

		state = STATE_WAITING_RETRY;
		rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	}

	iv_timer_register(&rx_timeout);
}

static void send_keepalive(void *cookie)
{
	static uint8_t keepalive[] = { 0x00, 0x00 };

	fprintf(stderr, "sending keepalive\n");

	if (state != STATE_CONNECTED)
		abort();

	iv_validate_now();

	if (pconn_record_send(&conn, keepalive, 2)) {
		state = STATE_WAITING_RETRY;

		pconn_destroy(&conn);
		close(connectfd.fd);

		iv_timer_unregister(&rx_timeout);
		rx_timeout.expires = iv_now;
		rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		iv_timer_register(&rx_timeout);

		return;
	}

	keepalive_timer.expires = iv_now;
	keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&keepalive_timer);
}

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	if (state == STATE_RESOLVE) {
		iv_getaddrinfo_cancel(&addrinfo);
	} else if (state == STATE_CONNECT) {
		iv_fd_unregister(&connectfd);
		close(connectfd.fd);
	} else if (state == STATE_TLS_HANDSHAKE) {
		pconn_destroy(&conn);
		close(connectfd.fd);
	} else if (state == STATE_CONNECTED) {
		pconn_destroy(&conn);
		close(connectfd.fd);
	} else if (state == STATE_WAITING_RETRY) {
	} else {
		abort();
	}

	tun_interface_unregister(&tun);

	if (iv_timer_registered(&rx_timeout))
		iv_timer_unregister(&rx_timeout);

	if (iv_timer_registered(&keepalive_timer))
		iv_timer_unregister(&keepalive_timer);

	iv_signal_unregister(&sigint);
}

int main(void)
{
	gnutls_global_init();

	iv_init();

	server = "localhost";
	serverport = "19275";
	itf = "tapc%d";
	if (x509_read_privkey(&key, "client.key") < 0)
		return 1;

	state = STATE_RESOLVE;

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_NUMERICSERV;

	addrinfo.node = server;
	addrinfo.service = serverport;
	addrinfo.hints = &hints;
	addrinfo.cookie = NULL;
	addrinfo.handler = resolve_complete;
	if (iv_getaddrinfo_submit(&addrinfo) < 0)
		return 1;

	IV_FD_INIT(&connectfd);
	connectfd.cookie = NULL;
	connectfd.handler_out = connect_done;

	tun.itfname = itf;
	tun.cookie = NULL;
	tun.got_packet = got_packet;
	if (tun_interface_register(&tun) < 0)
		return 1;

	conn.fd = -1;
	conn.role = PCONN_ROLE_CLIENT;
	conn.key = key;
	conn.cookie = NULL;
	conn.verify_key_id = verify_key_id;
	conn.handshake_done = handshake_done;
	conn.record_received = record_received;
	conn.connection_lost = connection_lost;

	IV_TIMER_INIT(&rx_timeout);
	iv_validate_now();
	rx_timeout.expires = iv_now;
	rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
	rx_timeout.cookie = NULL;
	rx_timeout.handler = rx_timeout_expired;
	iv_timer_register(&rx_timeout);

	IV_TIMER_INIT(&keepalive_timer);
	keepalive_timer.cookie = NULL;
	keepalive_timer.handler = send_keepalive;

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
