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

struct server_conn
{
	const char		*server;
	const char		*port;
	const char		*itf;
	gnutls_x509_privkey_t	key;

	int			state;
	struct iv_timer		rx_timeout;
	struct tun_interface	tun;
	union {
		struct {
			struct addrinfo		hints;
			struct iv_getaddrinfo	addrinfo;
		};
		struct {
			struct iv_fd		connectfd;
		};
		struct {
			struct pconn		pconn;
			struct iv_timer		keepalive_timer;
		};
	};
};

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

static void printhex(const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		printf("%.2x", a[i]);
		if (i < len - 1)
			printf(":");
	}
}

static int verify_key_id(void *_sc, const uint8_t *id, int len)
{
	printf("key id: ");
	printhex(id, len);
	printf("\n");

	return 0;
}

static void send_keepalive(void *_sc)
{
	static uint8_t keepalive[] = { 0x00, 0x00 };
	struct server_conn *sc = _sc;

	fprintf(stderr, "sending keepalive\n");

	if (sc->state != STATE_CONNECTED)
		abort();

	if (pconn_record_send(&sc->pconn, keepalive, 2)) {
		pconn_destroy(&sc->pconn);
		close(sc->pconn.fd);

		sc->state = STATE_WAITING_RETRY;

		iv_validate_now();

		iv_timer_unregister(&sc->rx_timeout);
		sc->rx_timeout.expires = iv_now;
		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		iv_timer_register(&sc->rx_timeout);

		return;
	}

	sc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&sc->keepalive_timer);
}

static void handshake_done(void *_sc)
{
	struct server_conn *sc = _sc;

	fprintf(stderr, "handshake_done\n");

	sc->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&sc->rx_timeout);
	sc->rx_timeout.expires = iv_now;
	sc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&sc->rx_timeout);

	IV_TIMER_INIT(&sc->keepalive_timer);
	sc->keepalive_timer.expires = iv_now;
	sc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	sc->keepalive_timer.cookie = sc;
	sc->keepalive_timer.handler = send_keepalive;
	iv_timer_register(&sc->keepalive_timer);
}

static void record_received(void *_sc, const uint8_t *rec, int len)
{
	struct server_conn *sc = _sc;
	int rlen;

	fprintf(stderr, "record_received, len = %d\n", len);

	iv_validate_now();

	iv_timer_unregister(&sc->rx_timeout);
	sc->rx_timeout.expires = iv_now;

	if (len <= 2)
		goto out;

	rlen = (rec[0] << 8) | rec[1];
	if (rlen + 2 != len)
		goto out;

	if (tun_interface_send_packet(&sc->tun, rec + 2, rlen) < 0) {
		pconn_destroy(&sc->pconn);
		close(sc->pconn.fd);

		iv_timer_unregister(&sc->keepalive_timer);

		sc->state = STATE_WAITING_RETRY;

		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		iv_timer_register(&sc->rx_timeout);

		return;
	}

out:
	sc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&sc->rx_timeout);
}

static void connection_lost(void *_sc)
{
	struct server_conn *sc = _sc;

	fprintf(stderr, "connection_lost\n");

	pconn_destroy(&sc->pconn);
	close(sc->pconn.fd);

	iv_timer_unregister(&sc->keepalive_timer);

	sc->state = STATE_WAITING_RETRY;

	iv_validate_now();

	iv_timer_unregister(&sc->rx_timeout);
	sc->rx_timeout.expires = iv_now;
	sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	iv_timer_register(&sc->rx_timeout);
}

static void connect_done(void *_sc)
{
	struct server_conn *sc = _sc;
	int fd = sc->connectfd.fd;
	socklen_t len;
	int ret;

	len = sizeof(ret);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		perror("connect_done,getsockopt(SO_ERROR)");
		return;
	}

	if (ret == EINPROGRESS)
		return;

	iv_timer_unregister(&sc->rx_timeout);

	if (iv_fd_registered(&sc->connectfd))
		iv_fd_unregister(&sc->connectfd);

	iv_validate_now();

	sc->rx_timeout.expires = iv_now;

	if (ret) {
		fprintf(stderr, "connect: %s\n", strerror(ret));
		close(fd);

		fprintf(stderr, "retrying in %d seconds\n", RETRY_WAIT_TIME);

		sc->state = STATE_WAITING_RETRY;

		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	} else {
		sc->state = STATE_TLS_HANDSHAKE;

		sc->rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;

		sc->pconn.fd = fd;
		sc->pconn.role = PCONN_ROLE_CLIENT;
		sc->pconn.key = sc->key;
		sc->pconn.cookie = sc;
		sc->pconn.verify_key_id = verify_key_id;
		sc->pconn.handshake_done = handshake_done;
		sc->pconn.record_received = record_received;
		sc->pconn.connection_lost = connection_lost;
		pconn_start(&sc->pconn);
	}

	iv_timer_register(&sc->rx_timeout);
}

static void resolve_complete(void *_sc, int rc, struct addrinfo *res)
{
	struct server_conn *sc = _sc;
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

	sc->state = STATE_CONNECT;

	IV_FD_INIT(&sc->connectfd);
	sc->connectfd.fd = fd;
	sc->connectfd.cookie = sc;
	sc->connectfd.handler_out = connect_done;

	if (ret == 0) {
		connect_done(sc);
	} else {
		iv_validate_now();

		iv_timer_unregister(&sc->rx_timeout);
		sc->rx_timeout.expires = iv_now;
		sc->rx_timeout.expires.tv_sec += CONNECT_TIMEOUT;
		iv_timer_register(&sc->rx_timeout);

		iv_fd_register(&sc->connectfd);
	}

	return;

err:
	if (res != NULL)
		freeaddrinfo(res);

	fprintf(stderr, "retrying in %d seconds\n", RETRY_WAIT_TIME);

	sc->state = STATE_WAITING_RETRY;

	iv_validate_now();

	iv_timer_unregister(&sc->rx_timeout);
	sc->rx_timeout.expires = iv_now;
	sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	iv_timer_register(&sc->rx_timeout);
}

static int start_resolve(struct server_conn *sc)
{
	if (sc->state != STATE_RESOLVE)
		abort();

	sc->hints.ai_family = PF_UNSPEC;
	sc->hints.ai_socktype = SOCK_STREAM;
	sc->hints.ai_protocol = 0;
	sc->hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_NUMERICSERV;

	sc->addrinfo.node = sc->server;
	sc->addrinfo.service = sc->port;
	sc->addrinfo.hints = &sc->hints;
	sc->addrinfo.cookie = sc;
	sc->addrinfo.handler = resolve_complete;

	return iv_getaddrinfo_submit(&sc->addrinfo);
}

static void got_packet(void *_sc, uint8_t *buf, int len)
{
	struct server_conn *sc = _sc;
	uint8_t sndbuf[len + 2];

	if (sc->state != STATE_CONNECTED)
		return;

	fprintf(stderr, "sending record, len = %d\n", len + 2);

	iv_timer_unregister(&sc->keepalive_timer);

	sndbuf[0] = len >> 8;
	sndbuf[1] = len & 0xff;
	memcpy(sndbuf + 2, buf, len);

	iv_validate_now();

	if (pconn_record_send(&sc->pconn, sndbuf, len + 2)) {
		pconn_destroy(&sc->pconn);
		close(sc->pconn.fd);

		sc->state = STATE_WAITING_RETRY;

		iv_timer_unregister(&sc->rx_timeout);
		sc->rx_timeout.expires = iv_now;
		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		iv_timer_register(&sc->rx_timeout);

		return;
	}

	sc->keepalive_timer.expires = iv_now;
	sc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&sc->keepalive_timer);
}

static void rx_timeout_expired(void *_sc)
{
	struct server_conn *sc = _sc;

	iv_validate_now();

	sc->rx_timeout.expires = iv_now;

	if (sc->state == STATE_WAITING_RETRY) {
		sc->state = STATE_RESOLVE;
		if (start_resolve(sc) == 0) {
			sc->rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
		} else {
			sc->state = STATE_WAITING_RETRY;
			sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
		}
	} else {
		if (sc->state == STATE_RESOLVE) {
			iv_getaddrinfo_cancel(&sc->addrinfo);
		} else if (sc->state == STATE_CONNECT) {
			iv_fd_unregister(&sc->connectfd);
			close(sc->connectfd.fd);
		} else if (sc->state == STATE_TLS_HANDSHAKE) {
			pconn_destroy(&sc->pconn);
			close(sc->pconn.fd);
		} else if (sc->state == STATE_CONNECTED) {
			pconn_destroy(&sc->pconn);
			close(sc->pconn.fd);
		} else {
			abort();
		}

		sc->state = STATE_WAITING_RETRY;
		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	}

	iv_timer_register(&sc->rx_timeout);
}

static int server_conn_register(struct server_conn *sc)
{
	sc->state = STATE_RESOLVE;

	IV_TIMER_INIT(&sc->rx_timeout);
	iv_validate_now();
	sc->rx_timeout.expires = iv_now;
	sc->rx_timeout.cookie = sc;
	sc->rx_timeout.handler = rx_timeout_expired;

	sc->tun.itfname = sc->itf;
	sc->tun.cookie = sc;
	sc->tun.got_packet = got_packet;
	if (tun_interface_register(&sc->tun) < 0)
		return 1;

	if (start_resolve(sc) < 0) {
		sc->rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
	} else {
		sc->state = STATE_WAITING_RETRY;
		sc->rx_timeout.expires.tv_sec += RETRY_WAIT_TIME;
	}

	iv_timer_register(&sc->rx_timeout);

	return 0;
}

static void server_conn_unregister(struct server_conn *sc)
{
	if (iv_timer_registered(&sc->rx_timeout))
		iv_timer_unregister(&sc->rx_timeout);

	tun_interface_unregister(&sc->tun);

	if (sc->state == STATE_RESOLVE) {
		iv_getaddrinfo_cancel(&sc->addrinfo);
	} else if (sc->state == STATE_CONNECT) {
		iv_fd_unregister(&sc->connectfd);
		close(sc->connectfd.fd);
	} else if (sc->state == STATE_TLS_HANDSHAKE) {
		pconn_destroy(&sc->pconn);
		close(sc->pconn.fd);
	} else if (sc->state == STATE_CONNECTED) {
		pconn_destroy(&sc->pconn);
		close(sc->pconn.fd);
		if (iv_timer_registered(&sc->keepalive_timer))
			iv_timer_unregister(&sc->keepalive_timer);
	} else if (sc->state == STATE_WAITING_RETRY) {
	} else {
		abort();
	}
}

static struct server_conn sc;
static struct iv_signal sigint;

static void got_sigint(void *_dummy)
{
	fprintf(stderr, "SIGINT received, shutting down\n");

	iv_signal_unregister(&sigint);

	server_conn_unregister(&sc);
}

int main(void)
{
	gnutls_global_init();

	iv_init();

	sc.server = "localhost";
	sc.port = "19275";
	sc.itf = "tapc%d";
	if (x509_read_privkey(&sc.key, "client.key") < 0)
		return 1;

	server_conn_register(&sc);

	IV_SIGNAL_INIT(&sigint);
	sigint.signum = SIGINT;
	sigint.flags = 0;
	sigint.cookie = NULL;
	sigint.handler = got_sigint;
	iv_signal_register(&sigint);

	iv_main();

	iv_deinit();

	gnutls_x509_privkey_deinit(sc.key);

	gnutls_global_deinit();

	return 0;
}
