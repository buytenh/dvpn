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
#include "tun.h"
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

		tc->set_state(tc->cookie, 0);
		itf_set_state(tun_interface_get_name(&tc->tun), 0);

		tconn_destroy(&tc->tconn);
		close(tc->tconn.fd);

		iv_timer_unregister(&tc->keepalive_timer);

		tc->state = STATE_WAITING_RETRY;

		iv_validate_now();

		iv_timer_unregister(&tc->rx_timeout);
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += SHORT_RETRY_WAIT_TIME;
		iv_timer_register(&tc->rx_timeout);
	}
}

static void handshake_done(void *_tc, char *desc)
{
	struct tconn_connect *tc = _tc;
	int i;
	socklen_t len;
	uint8_t id[NODE_ID_LEN];
	uint8_t addr[16];

	fprintf(stderr, "%s: handshake done, using %s\n", tc->name, desc);

	i = 1;
	if (setsockopt(tc->tconn.fd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt(SOL_TCP, TCP_NODELAY)");
		abort();
	}

	len = sizeof(i);
	if (getsockopt(tc->tconn.fd, SOL_TCP, TCP_MAXSEG, &i, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_MAXSEG)");
		abort();
	}

	i -= 5 + 8 + 3 + 16;
	if (i < 1280)
		i = 1280;
	else if (i > 1500)
		i = 1500;

	fprintf(stderr, "%s: setting interface MTU to %d\n", tc->name, i);
	itf_set_mtu(tun_interface_get_name(&tc->tun), i);

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

	itf_set_state(tun_interface_get_name(&tc->tun), 1);

	x509_get_key_id(id, tc->key);

	v6_linklocal_addr_from_key_id(addr, id);
	itf_add_addr_v6(tun_interface_get_name(&tc->tun), addr, 10);

	v6_global_addr_from_key_id(addr, id);
	itf_add_addr_v6(tun_interface_get_name(&tc->tun), addr, 128);

	v6_global_addr_from_key_id(addr, tc->fingerprint);
	itf_add_route_v6_direct(tun_interface_get_name(&tc->tun), addr);

	tc->set_state(tc->cookie, 1);
}

static void record_received(void *_tc, const uint8_t *rec, int len)
{
	struct tconn_connect *tc = _tc;
	int rlen;

	iv_validate_now();

	iv_timer_unregister(&tc->rx_timeout);
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->rx_timeout);

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	if (tun_interface_send_packet(&tc->tun, rec + 3, rlen) < 0) {
		fprintf(stderr, "%s: error forwarding received packet "
				"to tun interface, disconnecting and "
				"retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);

		itf_set_state(tun_interface_get_name(&tc->tun), 0);
		tc->set_state(tc->cookie, 0);

		tconn_destroy(&tc->tconn);
		close(tc->tconn.fd);

		iv_timer_unregister(&tc->keepalive_timer);

		tc->state = STATE_WAITING_RETRY;

		iv_validate_now();

		iv_timer_unregister(&tc->rx_timeout);
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += SHORT_RETRY_WAIT_TIME;
		iv_timer_register(&tc->rx_timeout);
	}
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

	if (tc->state == STATE_CONNECTED) {
		tc->set_state(tc->cookie, 0);
		itf_set_state(tun_interface_get_name(&tc->tun), 0);
	}

	tconn_destroy(&tc->tconn);
	close(tc->tconn.fd);

	if (tc->state == STATE_CONNECTED &&
	    iv_timer_registered(&tc->keepalive_timer)) {
		iv_timer_unregister(&tc->keepalive_timer);
	}

	tc->state = STATE_WAITING_RETRY;

	iv_validate_now();

	iv_timer_unregister(&tc->rx_timeout);
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += waittime;
	iv_timer_register(&tc->rx_timeout);
}

static void connect_success(struct tconn_connect *tc, int fd)
{
	fprintf(stderr, "%s: connection established, starting TLS handshake\n",
		tc->name);

	freeaddrinfo(tc->res);

	tc->state = STATE_TLS_HANDSHAKE;

	iv_validate_now();
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;
	iv_timer_register(&tc->rx_timeout);

	tc->tconn.fd = fd;
	tc->tconn.role = TCONN_ROLE_CLIENT;
	tc->tconn.key = tc->key;
	tc->tconn.cookie = tc;
	tc->tconn.verify_key_id = verify_key_id;
	tc->tconn.handshake_done = handshake_done;
	tc->tconn.record_received = record_received;
	tc->tconn.connection_lost = connection_lost;
	tconn_start(&tc->tconn);
}

static void try_connect(struct tconn_connect *tc)
{
	int fd;
	int ret;

	while (tc->rp != NULL) {
		fprintf(stderr, "%s: attempting connection to ", tc->name);
		print_address(stderr, tc->rp->ai_addr);
		fprintf(stderr, "\n");

		fd = socket(tc->rp->ai_family, tc->rp->ai_socktype,
			    tc->rp->ai_protocol);

		if (fd >= 0) {
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

			ret = connect(fd, tc->rp->ai_addr, tc->rp->ai_addrlen);
			if (ret == 0 || errno == EINPROGRESS)
				break;

			fprintf(stderr, "%s: connect error '%s'\n",
				tc->name, strerror(errno));
			close(fd);
		}

		tc->rp = tc->rp->ai_next;
	}

	if (tc->rp == NULL) {
		freeaddrinfo(tc->res);

		fprintf(stderr, "%s: error connecting, retrying in %d "
				"seconds\n", tc->name, LONG_RETRY_WAIT_TIME);

		tc->state = STATE_WAITING_RETRY;

		iv_validate_now();
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += LONG_RETRY_WAIT_TIME;
		iv_timer_register(&tc->rx_timeout);

		return;
	}

	if (ret == 0) {
		connect_success(tc, fd);
	} else {
		iv_validate_now();
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += CONNECT_TIMEOUT;
		iv_timer_register(&tc->rx_timeout);

		tc->connectfd.fd = fd;
		iv_fd_register(&tc->connectfd);
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
	iv_fd_unregister(&tc->connectfd);

	if (ret == 0) {
		connect_success(tc, fd);
	} else {
		fprintf(stderr, "%s: connect error '%s'\n",
			tc->name, strerror(ret));
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

		tc->state = STATE_WAITING_RETRY;

		iv_validate_now();

		iv_timer_unregister(&tc->rx_timeout);
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += SHORT_RETRY_WAIT_TIME;
		iv_timer_register(&tc->rx_timeout);
	}
}

static int start_resolve(struct tconn_connect *tc)
{
	int ret;

	if (tc->state != STATE_RESOLVE)
		abort();

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

static void got_packet(void *_tc, uint8_t *buf, int len)
{
	struct tconn_connect *tc = _tc;
	uint8_t sndbuf[len + 3];

	if (tc->state != STATE_CONNECTED)
		return;

	iv_timer_unregister(&tc->keepalive_timer);

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	iv_validate_now();

	if (tconn_record_send(&tc->tconn, sndbuf, len + 3)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting "
				"and retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);

		tc->set_state(tc->cookie, 0);
		itf_set_state(tun_interface_get_name(&tc->tun), 0);

		tconn_destroy(&tc->tconn);
		close(tc->tconn.fd);

		tc->state = STATE_WAITING_RETRY;

		iv_timer_unregister(&tc->rx_timeout);
		tc->rx_timeout.expires = iv_now;
		tc->rx_timeout.expires.tv_sec += SHORT_RETRY_WAIT_TIME;
		iv_timer_register(&tc->rx_timeout);

		return;
	}

	tc->keepalive_timer.expires = iv_now;
	tc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&tc->keepalive_timer);
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
			close(tc->tconn.fd);
			waittime = LONG_RETRY_WAIT_TIME;
		} else if (tc->state == STATE_CONNECTED) {
			fprintf(stderr, "receive timeout");
			tc->set_state(tc->cookie, 0);
			itf_set_state(tun_interface_get_name(&tc->tun), 0);
			tconn_destroy(&tc->tconn);
			close(tc->tconn.fd);
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

int tconn_connect_start(struct tconn_connect *tc)
{
	tc->state = STATE_RESOLVE;

	tc->tun.itfname = tc->tunitf;
	tc->tun.cookie = tc;
	tc->tun.got_packet = got_packet;
	if (tun_interface_register(&tc->tun) < 0)
		return 1;

	itf_set_state(tun_interface_get_name(&tc->tun), 0);

	IV_TIMER_INIT(&tc->rx_timeout);
	iv_validate_now();
	tc->rx_timeout.expires = iv_now;
	tc->rx_timeout.cookie = tc;
	tc->rx_timeout.handler = rx_timeout_expired;

	if (start_resolve(tc) == 0) {
		tc->rx_timeout.expires.tv_sec += RESOLVE_TIMEOUT;
	} else {
		fprintf(stderr, "%s: error starting address "
				"resolution, retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);

		tc->state = STATE_WAITING_RETRY;
		tc->rx_timeout.expires.tv_sec += SHORT_RETRY_WAIT_TIME;
	}

	iv_timer_register(&tc->rx_timeout);

	return 0;
}

void tconn_connect_destroy(struct tconn_connect *tc)
{
	tun_interface_unregister(&tc->tun);

	iv_timer_unregister(&tc->rx_timeout);

	if (tc->state == STATE_RESOLVE) {
		iv_getaddrinfo_cancel(&tc->addrinfo);
	} else if (tc->state == STATE_CONNECT) {
		freeaddrinfo(tc->res);
		iv_fd_unregister(&tc->connectfd);
		close(tc->connectfd.fd);
	} else if (tc->state == STATE_TLS_HANDSHAKE) {
		tconn_destroy(&tc->tconn);
		close(tc->tconn.fd);
	} else if (tc->state == STATE_CONNECTED) {
		tconn_destroy(&tc->tconn);
		close(tc->tconn.fd);
		iv_timer_unregister(&tc->keepalive_timer);
	} else if (tc->state == STATE_WAITING_RETRY) {
	} else {
		abort();
	}
}
