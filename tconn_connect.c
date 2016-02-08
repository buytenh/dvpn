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
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <string.h>
#include "conf.h"
#include "itf.h"
#include "iv_getaddrinfo.h"
#include "tconn.h"
#include "tconn_connect.h"
#include "util.h"
#include "x509.h"

#define STATE_RESOLVE		1
#define STATE_CONNECT		2
#define STATE_TLS_HANDSHAKE	3
#define STATE_CONNECTED		4
#define STATE_WAITING_RETRY	5

#define RESOLVE_TIMEOUT		10
#define CONNECT_TIMEOUT		10
#define HANDSHAKE_TIMEOUT	30
#define KEEPALIVE_INTERVAL	30
#define SHORT_RETRY_WAIT_TIME	2
#define LONG_RETRY_WAIT_TIME	10

static int verify_key_id(void *_tc, const uint8_t *id)
{
	struct tconn_connect *tc = _tc;

	fprintf(stderr, "%s: peer key ID ", tc->name);
	printhex(stderr, id, NODE_ID_LEN);

	if (memcmp(tc->fingerprint, id, NODE_ID_LEN)) {
		fprintf(stderr, " - mismatch\n");
		return 1;
	}

	fprintf(stderr, " - OK\n");

	return 0;
}

static void schedule_retry(struct tconn_connect *tc, int waittime)
{
	if (tc->state == STATE_CONNECTED)
		tc->set_state(tc->cookie, 0);

	if (tc->state == STATE_TLS_HANDSHAKE || tc->state == STATE_CONNECTED) {
		tconn_destroy(&tc->tconn);
		iv_fd_unregister(&tc->tconnfd);
		close(tc->tconnfd.fd);
	}

	if (tc->state == STATE_CONNECTED)
		iv_timer_unregister(&tc->keepalive_timer);

	tc->state = STATE_WAITING_RETRY;

	if (iv_timer_registered(&tc->rx_timeout))
		iv_timer_unregister(&tc->rx_timeout);

	iv_validate_now();
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += waittime;
	iv_timer_register(&tc->rx_timeout);
}

static void send_keepalive(void *_tc)
{
	static uint8_t keepalive[] = { 0x00, 0x00, 0x00 };
	struct tconn_connect *tc = _tc;

	if (tc->state != STATE_CONNECTED)
		abort();

	tc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->keepalive_timer);

	if (tconn_record_send(&tc->tconn, keepalive, 3)) {
		fprintf(stderr, "%s: error sending keepalive, disconnecting "
				"and retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}

static void handshake_done(void *_tc, char *desc)
{
	struct tconn_connect *tc = _tc;

	fprintf(stderr, "%s: handshake done, using %s\n", tc->name, desc);

	tc->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&tc->rx_timeout);
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->rx_timeout);

	IV_TIMER_INIT(&tc->keepalive_timer);
	tc->keepalive_timer.expires = iv_now;
	tc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	tc->keepalive_timer.cookie = tc;
	tc->keepalive_timer.handler = send_keepalive;
	iv_timer_register(&tc->keepalive_timer);

	tc->set_state(tc->cookie, 1);
}

static void record_received(void *_tc, const uint8_t *rec, int len)
{
	struct tconn_connect *tc = _tc;

	iv_validate_now();

	iv_timer_unregister(&tc->rx_timeout);
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->rx_timeout);

	tc->record_received(tc->cookie, rec, len);
}

static void connection_lost(void *_tc)
{
	struct tconn_connect *tc = _tc;
	int waittime;

	if (tc->state == STATE_CONNECTED)
		waittime = SHORT_RETRY_WAIT_TIME;
	else
		waittime = LONG_RETRY_WAIT_TIME;

	fprintf(stderr, "%s: connection lost, retrying in %d seconds\n",
		tc->name, waittime);
	schedule_retry(tc, waittime);
}

static void connect_success(struct tconn_connect *tc)
{
	fprintf(stderr, "%s: connection established, starting TLS handshake\n",
		tc->name);

	freeaddrinfo(tc->res);

	tc->state = STATE_TLS_HANDSHAKE;

	iv_validate_now();
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;
	iv_timer_register(&tc->rx_timeout);

	tc->tconn.fd = &tc->tconnfd;
	tc->tconn.role = TCONN_ROLE_CLIENT;
	tc->tconn.privkey = tc->privkey;
	tc->tconn.cookie = tc;
	tc->tconn.verify_key_id = verify_key_id;
	tc->tconn.handshake_done = handshake_done;
	tc->tconn.record_received = record_received;
	tc->tconn.connection_lost = connection_lost;
	tconn_start(&tc->tconn);
}

static int try_connect_one(struct tconn_connect *tc)
{
	struct addrinfo *rp = tc->rp;
	int fd;
	int ret;

	fprintf(stderr, "%s: attempting connection to ", tc->name);
	print_address(stderr, rp->ai_addr);
	fprintf(stderr, "\n");

	fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (fd < 0)
		return -1;

	tc->connectfd.fd = fd;
	iv_fd_register(&tc->connectfd);

	ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
	if (ret < 0 && errno != EINPROGRESS) {
		fprintf(stderr, "%s: connect error '%s'\n",
			tc->name, strerror(errno));
		iv_fd_unregister(&tc->connectfd);
		close(fd);
		return -1;
	}

	return !!(ret == 0);
}

static void try_connect(struct tconn_connect *tc)
{
	int ret;

	while (tc->rp != NULL) {
		ret = try_connect_one(tc);
		if (ret >= 0)
			break;

		tc->rp = tc->rp->ai_next;
	}

	if (tc->rp == NULL) {
		freeaddrinfo(tc->res);

		fprintf(stderr, "%s: error connecting, retrying in %d "
				"seconds\n", tc->name, LONG_RETRY_WAIT_TIME);
		schedule_retry(tc, LONG_RETRY_WAIT_TIME);

		return;
	}

	if (ret) {
		connect_success(tc);
	} else {
		iv_validate_now();
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += CONNECT_TIMEOUT;
		iv_timer_register(&tc->rx_timeout);
	}
}

static void connect_pollout(void *_tc)
{
	struct tconn_connect *tc = _tc;
	int fd;
	socklen_t len;
	int ret;

	fd = tc->connectfd.fd;

	len = sizeof(ret);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		fprintf(stderr, "%s: getsockopt error '%s'\n",
			tc->name, strerror(errno));
		return;
	}

	if (ret == EINPROGRESS)
		return;

	iv_timer_unregister(&tc->rx_timeout);

	if (ret == 0) {
		connect_success(tc);
	} else {
		fprintf(stderr, "%s: connect error '%s'\n",
			tc->name, strerror(ret));

		iv_fd_unregister(&tc->connectfd);
		close(fd);

		tc->rp = tc->rp->ai_next;
		try_connect(tc);
	}
}

static void resolve_complete(void *_tc, int rc, struct addrinfo *res)
{
	struct tconn_connect *tc = _tc;

	if (rc == 0) {
		fprintf(stderr, "%s: address resolution complete\n",
			tc->name);

		tc->state = STATE_CONNECT;

		iv_timer_unregister(&tc->rx_timeout);

		tc->res = res;
		tc->rp = res;

		IV_FD_INIT(&tc->connectfd);
		tc->connectfd.cookie = tc;
		tc->connectfd.handler_out = connect_pollout;

		try_connect(tc);
	} else {
		if (res != NULL)
			freeaddrinfo(res);

		fprintf(stderr, "%s: address resolution returned error '%s', "
				"retrying in %d seconds\n",
			tc->name, gai_strerror(rc), SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}

static int start_resolve(struct tconn_connect *tc)
{
	int ret;

	if (tc->state != STATE_RESOLVE)
		abort();

	memset(&tc->hints, 0, sizeof(tc->hints));
	tc->hints.ai_family = PF_UNSPEC;
	tc->hints.ai_socktype = SOCK_STREAM;
	tc->hints.ai_protocol = 0;
	tc->hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_NUMERICSERV;

	tc->addrinfo.node = tc->hostname;
	tc->addrinfo.service = tc->port;
	tc->addrinfo.hints = &tc->hints;
	tc->addrinfo.cookie = tc;
	tc->addrinfo.handler = resolve_complete;

	ret = iv_getaddrinfo_submit(&tc->addrinfo);
	if (ret == 0)
		fprintf(stderr, "%s: starting address resolution\n", tc->name);

	return ret;
}

static void rx_timeout_expired(void *_tc)
{
	struct tconn_connect *tc = _tc;
	int waittime;

	if (tc->state == STATE_CONNECT) {
		fprintf(stderr, "%s: connect timed out\n", tc->name);

		iv_fd_unregister(&tc->connectfd);
		close(tc->connectfd.fd);

		tc->rp = tc->rp->ai_next;
		try_connect(tc);

		return;
	}

	if (tc->state == STATE_WAITING_RETRY) {
		tc->state = STATE_RESOLVE;
		if (start_resolve(tc) == 0) {
			waittime = RESOLVE_TIMEOUT;
		} else {
			fprintf(stderr, "%s: error starting address "
					"resolution", tc->name);

			tc->state = STATE_WAITING_RETRY;
			waittime = SHORT_RETRY_WAIT_TIME;
		}
	} else {
		fprintf(stderr, "%s: ", tc->name);

		if (tc->state == STATE_RESOLVE) {
			fprintf(stderr, "address resolution timed out");
			iv_getaddrinfo_cancel(&tc->addrinfo);
			waittime = SHORT_RETRY_WAIT_TIME;
		} else if (tc->state == STATE_TLS_HANDSHAKE) {
			fprintf(stderr, "TLS handshake timed out");
			tconn_destroy(&tc->tconn);
			iv_fd_unregister(&tc->tconnfd);
			close(tc->tconnfd.fd);
			waittime = LONG_RETRY_WAIT_TIME;
		} else if (tc->state == STATE_CONNECTED) {
			fprintf(stderr, "receive timeout");
			tc->set_state(tc->cookie, 0);
			tconn_destroy(&tc->tconn);
			iv_fd_unregister(&tc->tconnfd);
			close(tc->tconnfd.fd);
			iv_timer_unregister(&tc->keepalive_timer);
			waittime = SHORT_RETRY_WAIT_TIME;
		} else {
			abort();
		}

		tc->state = STATE_WAITING_RETRY;
	}

	if (tc->state == STATE_WAITING_RETRY)
		fprintf(stderr, ", retrying in %d seconds\n", waittime);

	iv_validate_now();

	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += waittime;
	iv_timer_register(&tc->rx_timeout);
}

void tconn_connect_start(struct tconn_connect *tc)
{
	tc->state = STATE_RESOLVE;

	IV_TIMER_INIT(&tc->rx_timeout);
	tc->rx_timeout.cookie = tc;
	tc->rx_timeout.handler = rx_timeout_expired;

	if (start_resolve(tc)) {
		fprintf(stderr, "%s: error starting address "
				"resolution, retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}

	iv_validate_now();
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
	iv_timer_register(&tc->rx_timeout);
}

void tconn_connect_destroy(struct tconn_connect *tc)
{
	iv_timer_unregister(&tc->rx_timeout);

	if (tc->state == STATE_RESOLVE) {
		iv_getaddrinfo_cancel(&tc->addrinfo);
	} else if (tc->state == STATE_CONNECT) {
		freeaddrinfo(tc->res);
		iv_fd_unregister(&tc->connectfd);
		close(tc->connectfd.fd);
	} else if (tc->state == STATE_TLS_HANDSHAKE) {
		tconn_destroy(&tc->tconn);
		iv_fd_unregister(&tc->tconnfd);
		close(tc->tconnfd.fd);
	} else if (tc->state == STATE_CONNECTED) {
		tconn_destroy(&tc->tconn);
		iv_fd_unregister(&tc->tconnfd);
		close(tc->tconnfd.fd);
		iv_timer_unregister(&tc->keepalive_timer);
	} else if (tc->state == STATE_WAITING_RETRY) {
	} else {
		abort();
	}
}

int tconn_connect_get_maxseg(struct tconn_connect *tc)
{
	int mseg;
	socklen_t len;

	if (tc->state != STATE_CONNECTED)
		return -1;

	len = sizeof(mseg);
	if (getsockopt(tc->tconnfd.fd, SOL_TCP, TCP_MAXSEG, &mseg, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_MAXSEG)");
		return -1;
	}

	return mseg;
}

void tconn_connect_record_send(struct tconn_connect *tc,
			       const uint8_t *rec, int len)
{
	if (tc->state != STATE_CONNECTED)
		return;

	iv_validate_now();

	iv_timer_unregister(&tc->keepalive_timer);
	tc->keepalive_timer.expires = iv_now;
	tc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->keepalive_timer);

	if (tconn_record_send(&tc->tconn, rec, len)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting "
				"and retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}
