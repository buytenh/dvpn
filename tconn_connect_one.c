/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2015, 2016 Lennert Buytenhek
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
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <netinet/tcp.h>
#include <string.h>
#include "conf.h"
#include "tconn.h"
#include "tconn_connect_one.h"
#include "util.h"
#include "x509.h"

#define STATE_CONNECT		1
#define STATE_TLS_HANDSHAKE	2
#define STATE_CONNECTED		3
#define STATE_FAILED		4

#define CONNECT_TIMEOUT		10
#define HANDSHAKE_TIMEOUT	15
#define KEEPALIVE_INTERVAL	15
#define KEEPALIVE_TIMEOUT	20

static void state_destroy(struct tconn_connect_one *tco)
{
	if (iv_timer_registered(&tco->rx_timeout))
		iv_timer_unregister(&tco->rx_timeout);

	if (tco->state == STATE_TLS_HANDSHAKE ||
	    tco->state == STATE_CONNECTED) {
		tconn_destroy(&tco->tconn);
	}

	if (tco->state == STATE_CONNECT ||
	    tco->state == STATE_TLS_HANDSHAKE ||
	    tco->state == STATE_CONNECTED) {
		iv_fd_unregister(&tco->fd);
		close(tco->fd.fd);
	}

	if (tco->state == STATE_CONNECTED)
		iv_timer_unregister(&tco->keepalive_timer);
}

static void connection_failed(struct tconn_connect_one *tco)
{
	state_destroy(tco);

	tco->state = STATE_FAILED;
	tco->connection_failed(tco->cookie);
}

static void rx_timeout_expired(void *_tco)
{
	struct tconn_connect_one *tco = _tco;

	switch (tco->state) {
	case STATE_CONNECT:
		fprintf(stderr, "%s: connect timed out\n", tco->name);
		break;
	case STATE_TLS_HANDSHAKE:
		fprintf(stderr, "%s: TLS handshake timed out\n", tco->name);
		break;
	case STATE_CONNECTED:
		fprintf(stderr, "%s: receive timeout\n", tco->name);
		break;
	}

	connection_failed(tco);
}

static int verify_key_ids(void *_tco, const uint8_t *ids, int num)
{
	struct tconn_connect_one *tco = _tco;
	int i;

	fprintf(stderr, "%s: peer key ID ", tco->name);
	print_fingerprint(stderr, ids);

	if (tco->cnameid != NULL) {
		for (i = 0; i < num; i++) {
			const uint8_t *id;

			id = ids + (i * NODE_ID_LEN);
			if (!memcmp(tco->cnameid, id, NODE_ID_LEN))
				break;
		}

		if (i == num) {
			fprintf(stderr, " - does not match its CNAME\n");
			return 1;
		}

		if (tco->fp_type == CONF_FP_TYPE_ANY ||
		    tco->fp_type == CONF_FP_TYPE_CNAME) {
			fprintf(stderr, " - have CNAME match\n");
			return 0;
		}
	}

	if (tco->fp_type == CONF_FP_TYPE_ANY) {
		fprintf(stderr, " - matches 'any'\n");
		return 0;
	}

	if (tco->fp_type == CONF_FP_TYPE_CNAME) {
		fprintf(stderr, " - don't have CNAME match\n");
		return 1;
	}

	for (i = 0; i < num; i++) {
		const uint8_t *id;

		id = ids + (i * NODE_ID_LEN);
		if (!memcmp(tco->fingerprint, id, NODE_ID_LEN)) {
			fprintf(stderr, " - OK%s\n",
				(i != 0) ? " (via role certificate)" : "");
			memcpy(tco->id, ids, NODE_ID_LEN);
			return 0;
		}
	}

	fprintf(stderr, " - no matches\n");

	return 1;
}

static void send_keepalive(void *_tco)
{
	static uint8_t keepalive[] = { 0x00, 0x00, 0x00 };
	struct tconn_connect_one *tco = _tco;

	if (tco->state != STATE_CONNECTED)
		abort();

	timespec_add_ms(&tco->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
	iv_timer_register(&tco->keepalive_timer);

	if (tconn_record_send(&tco->tconn, keepalive, 3)) {
		fprintf(stderr, "%s: error sending keepalive, disconnecting\n",
			tco->name);
		connection_failed(tco);
	}
}

static void handshake_done(void *_tco, char *desc)
{
	struct tconn_connect_one *tco = _tco;

	fprintf(stderr, "%s: handshake done, using %s\n", tco->name, desc);

	tco->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&tco->rx_timeout);
	tco->rx_timeout.expires = iv_now;
	timespec_add_ms(&tco->rx_timeout.expires,
			1000 * KEEPALIVE_TIMEOUT, 1000 * KEEPALIVE_TIMEOUT);
	iv_timer_register(&tco->rx_timeout);

	IV_TIMER_INIT(&tco->keepalive_timer);
	tco->keepalive_timer.expires = iv_now;
	timespec_add_ms(&tco->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
	tco->keepalive_timer.cookie = tco;
	tco->keepalive_timer.handler = send_keepalive;
	iv_timer_register(&tco->keepalive_timer);

	tco->connected(tco->cookie, tco->id);
}

static void record_received(void *_tco, const uint8_t *rec, int len)
{
	struct tconn_connect_one *tco = _tco;

	iv_timer_unregister(&tco->rx_timeout);
	iv_validate_now();
	tco->rx_timeout.expires = iv_now;
	timespec_add_ms(&tco->rx_timeout.expires,
			1000 * KEEPALIVE_TIMEOUT, 1000 * KEEPALIVE_TIMEOUT);
	iv_timer_register(&tco->rx_timeout);

	tco->record_received(tco->cookie, rec, len);
}

static void connection_lost(void *_tco)
{
	struct tconn_connect_one *tco = _tco;

	connection_failed(tco);
}

static int start_handshake(struct tconn_connect_one *tco)
{
	fprintf(stderr, "%s: connection established, starting TLS handshake\n",
		tco->name);

	tco->tconn.fd = &tco->fd;
	tco->tconn.role = TCONN_ROLE_CLIENT;
	tco->tconn.mykey = tco->mykey;
	tco->tconn.numcrts = tco->numcrts;
	tco->tconn.mycrts = tco->mycrts;
	tco->tconn.cookie = tco;
	tco->tconn.verify_key_ids = verify_key_ids;
	tco->tconn.handshake_done = handshake_done;
	tco->tconn.record_received = record_received;
	tco->tconn.connection_lost = connection_lost;
	if (tconn_start(&tco->tconn) < 0)
		return -1;

	tco->state = STATE_TLS_HANDSHAKE;

	iv_validate_now();
	tco->rx_timeout.expires = iv_now;
	timespec_add_ms(&tco->rx_timeout.expires,
			1000 * HANDSHAKE_TIMEOUT, 1000 * HANDSHAKE_TIMEOUT);
	iv_timer_register(&tco->rx_timeout);

	return 0;
}

static void connect_pollout(void *_tco)
{
	struct tconn_connect_one *tco = _tco;
	socklen_t len;
	int ret;

	len = sizeof(ret);
	if (getsockopt(tco->fd.fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		fprintf(stderr, "%s: getsockopt error '%s'\n",
			tco->name, strerror(errno));
		return;
	}

	if (ret == EINPROGRESS)
		return;

	iv_timer_unregister(&tco->rx_timeout);

	if (ret) {
		fprintf(stderr, "%s: connect error '%s'\n",
			tco->name, strerror(ret));
		connection_failed(tco);
		return;
	}

	if (start_handshake(tco))
		connection_failed(tco);
}

int tconn_connect_one_connect(struct tconn_connect_one *tco)
{
	int fd;
	int ret;

	tco->state = STATE_CONNECT;

	IV_TIMER_INIT(&tco->rx_timeout);
	tco->rx_timeout.cookie = tco;
	tco->rx_timeout.handler = rx_timeout_expired;

	fd = socket(tco->addr->sa_family, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	IV_FD_INIT(&tco->fd);
	tco->fd.cookie = tco;
	tco->fd.handler_out = connect_pollout;
	tco->fd.fd = fd;
	iv_fd_register(&tco->fd);

	ret = connect(fd, tco->addr, tco->addrlen);
	if (ret < 0 && errno != EINPROGRESS) {
		fprintf(stderr, "%s: connect error '%s'\n",
			tco->name, strerror(errno));
		iv_fd_unregister(&tco->fd);
		close(fd);
		return -1;
	}

	if (ret == 0) {
		if (start_handshake(tco)) {
			iv_fd_unregister(&tco->fd);
			close(fd);
			return -1;
		}
		return 0;
	}

	iv_validate_now();
	tco->rx_timeout.expires = iv_now;
	timespec_add_ms(&tco->rx_timeout.expires,
			1000 * CONNECT_TIMEOUT, 1000 * CONNECT_TIMEOUT);
	iv_timer_register(&tco->rx_timeout);

	return 0;
}

void tconn_connect_one_disconnect(struct tconn_connect_one *tco)
{
	state_destroy(tco);
}

int tconn_connect_one_get_rtt(struct tconn_connect_one *tco)
{
	struct tcp_info info;
	socklen_t len;

	if (tco->state != STATE_CONNECTED)
		return -1;

	len = sizeof(info);
	if (getsockopt(tco->fd.fd, SOL_TCP, TCP_INFO, &info, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_INFO)");
		return -1;
	}

	return info.tcpi_rtt / 1000;
}

int tconn_connect_one_get_maxseg(struct tconn_connect_one *tco)
{
	int mseg;
	socklen_t len;

	if (tco->state != STATE_CONNECTED)
		return -1;

	len = sizeof(mseg);
	if (getsockopt(tco->fd.fd, SOL_TCP, TCP_MAXSEG, &mseg, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_MAXSEG)");
		return -1;
	}

	return mseg;
}

int tconn_connect_one_record_send(struct tconn_connect_one *tco,
				  const uint8_t *rec, int len)
{
	if (tco->state != STATE_CONNECTED)
		return 0;

	iv_timer_unregister(&tco->keepalive_timer);
	iv_validate_now();
	tco->keepalive_timer.expires = iv_now;
	timespec_add_ms(&tco->keepalive_timer.expires,
			900 * KEEPALIVE_INTERVAL, 1100 * KEEPALIVE_INTERVAL);
	iv_timer_register(&tco->keepalive_timer);

	if (tconn_record_send(&tco->tconn, rec, len)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting\n",
			tco->name);
		connection_failed(tco);
		return -1;
	}

	return 0;
}
