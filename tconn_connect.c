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
#include <iv.h>
#include <netdb.h>
#include <string.h>
#include "conf.h"
#include "iv_getaddrinfo.h"
#include "tconn.h"
#include "tconn_connect.h"
#include "tconn_connect_one.h"
#include "util.h"
#include "x509.h"

#define STATE_RESOLVE		1
#define STATE_CONNECT		2
#define STATE_CONNECTED		3
#define STATE_WAITING_RETRY	4

#define RESOLVE_TIMEOUT		10
#define SHORT_RETRY_WAIT_TIME	2
#define LONG_RETRY_WAIT_TIME	10

static void start_resolve(struct tconn_connect *tc);
static void try_connect(struct tconn_connect *tc);

static void retry_wait_time_expired(void *_tc)
{
	struct tconn_connect *tc = _tc;

	start_resolve(tc);
}

static void schedule_retry(struct tconn_connect *tc, int waittime)
{
	if (tc->state == STATE_CONNECTED)
		tc->disconnect(tc->conncookie);

	tc->state = STATE_WAITING_RETRY;

	IV_TIMER_INIT(&tc->retry_wait);
	iv_validate_now();
	tc->retry_wait.expires = iv_now;
	timespec_add_ms(&tc->retry_wait.expires,
			900 * waittime, 1100 * waittime);
	tc->retry_wait.cookie = tc;
	tc->retry_wait.handler = retry_wait_time_expired;
	iv_timer_register(&tc->retry_wait);
}

static void connected(void *_tc, const uint8_t *id)
{
	struct tconn_connect *tc = _tc;

	freeaddrinfo(tc->res);

	tc->state = STATE_CONNECTED;

	tc->conncookie = tc->new_conn(tc->cookie, tc, id);
	if (tc->conncookie == NULL) {
		tconn_connect_one_disconnect(&tc->tco);

		fprintf(stderr, "%s: handshake done but new connection "
				"refused, retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}

static void record_received(void *_tc, const uint8_t *rec, int len)
{
	struct tconn_connect *tc = _tc;

	tc->record_received(tc->conncookie, rec, len);
}

static void connection_failed(void *_tc)
{
	struct tconn_connect *tc = _tc;

	if (tc->state == STATE_CONNECT) {
		tconn_connect_one_disconnect(&tc->tco_connect);

		tc->rp = tc->rp->ai_next;
		try_connect(tc);
	} else {
		tconn_connect_one_disconnect(&tc->tco);

		fprintf(stderr, "%s: connection lost, retrying in %d "
				"seconds\n", tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}

static void try_connect(struct tconn_connect *tc)
{
	while (tc->rp != NULL) {
		struct addrinfo *rp = tc->rp;

		fprintf(stderr, "%s: attempting connection to ", tc->name);
		print_address(stderr, rp->ai_addr);
		fprintf(stderr, "\n");

		tc->tco_connect.addr = rp->ai_addr;
		tc->tco_connect.addrlen = rp->ai_addrlen;
		if (tconn_connect_one_connect(&tc->tco_connect) == 0)
			return;

		tc->rp = tc->rp->ai_next;
	}

	freeaddrinfo(tc->res);

	fprintf(stderr, "%s: error connecting, retrying in %d "
			"seconds\n", tc->name, LONG_RETRY_WAIT_TIME);
	schedule_retry(tc, LONG_RETRY_WAIT_TIME);
}

static void resolve_complete(void *_tc, int rc, struct addrinfo *res)
{
	struct tconn_connect *tc = _tc;

	iv_timer_unregister(&tc->resolve_timeout);

	if (rc == 0) {
		fprintf(stderr, "%s: address resolution complete\n", tc->name);

		tc->state = STATE_CONNECT;

		tc->tco_connect.name = tc->name;
		tc->tco_connect.mykey = tc->mykey;
		tc->tco_connect.numcrts = tc->numcrts;
		tc->tco_connect.mycrts = tc->mycrts;
		tc->tco_connect.fp_type = tc->fp_type;
		tc->tco_connect.fingerprint = tc->fingerprint;
		tc->tco_connect.cnameid = NULL;
		tc->tco_connect.cookie = tc;
		tc->tco_connect.connected = connected;
		tc->tco_connect.record_received = record_received;
		tc->tco_connect.connection_failed = connection_failed;

		tc->res = res;
		tc->rp = res;

		if (tc->res->ai_canonname != NULL &&
		    !parse_hostname_fingerprint(tc->cnameid,
						tc->res->ai_canonname)) {
			tc->tco_connect.cnameid = tc->cnameid;
		}

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

static void resolve_timeout_expired(void *_tc)
{
	struct tconn_connect *tc = _tc;

	iv_getaddrinfo_cancel(&tc->addrinfo);

	fprintf(stderr, "%s: address resolution timed out, retrying in %d "
			"seconds\n", tc->name, SHORT_RETRY_WAIT_TIME);
	schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
}

static void start_resolve(struct tconn_connect *tc)
{
	int ret;

	tc->state = STATE_RESOLVE;

	memset(&tc->hints, 0, sizeof(tc->hints));
	tc->hints.ai_family = PF_UNSPEC;
	tc->hints.ai_socktype = SOCK_STREAM;
	tc->hints.ai_protocol = 0;
	tc->hints.ai_flags = AI_CANONNAME | AI_V4MAPPED |
			     AI_ADDRCONFIG | AI_NUMERICSERV;

	tc->addrinfo.node = tc->hostname;
	tc->addrinfo.service = tc->port;
	tc->addrinfo.hints = &tc->hints;
	tc->addrinfo.cookie = tc;
	tc->addrinfo.handler = resolve_complete;

	ret = iv_getaddrinfo_submit(&tc->addrinfo);
	if (ret == 0) {
		fprintf(stderr, "%s: starting address resolution\n", tc->name);

		IV_TIMER_INIT(&tc->resolve_timeout);
		iv_validate_now();
		tc->resolve_timeout.expires = iv_now;
		timespec_add_ms(&tc->resolve_timeout.expires,
				1000 * RESOLVE_TIMEOUT, 1000 * RESOLVE_TIMEOUT);
		tc->resolve_timeout.cookie = tc;
		tc->resolve_timeout.handler = resolve_timeout_expired;
		iv_timer_register(&tc->resolve_timeout);
	} else {
		fprintf(stderr, "%s: error starting address "
				"resolution, retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}

void tconn_connect_start(struct tconn_connect *tc)
{
	start_resolve(tc);
}

void tconn_connect_destroy(struct tconn_connect *tc)
{
	if (tc->state == STATE_RESOLVE) {
		iv_getaddrinfo_cancel(&tc->addrinfo);
		iv_timer_unregister(&tc->resolve_timeout);
	} else if (tc->state == STATE_CONNECT) {
		tconn_connect_one_disconnect(&tc->tco_connect);
		freeaddrinfo(tc->res);
	} else if (tc->state == STATE_CONNECTED) {
		tconn_connect_one_disconnect(&tc->tco);
	} else if (tc->state == STATE_WAITING_RETRY) {
		iv_timer_unregister(&tc->retry_wait);
	} else {
		abort();
	}
}

int tconn_connect_get_rtt(void *conn)
{
	struct tconn_connect *tc = conn;

	if (tc->state != STATE_CONNECTED)
		return -1;

	return tconn_connect_one_get_rtt(&tc->tco);
}

int tconn_connect_get_maxseg(void *conn)
{
	struct tconn_connect *tc = conn;

	if (tc->state != STATE_CONNECTED)
		return -1;

	return tconn_connect_one_get_maxseg(&tc->tco);
}

void tconn_connect_record_send(void *conn, const uint8_t *rec, int len)
{
	struct tconn_connect *tc = conn;

	if (tc->state != STATE_CONNECTED)
		return;

	if (tconn_connect_one_record_send(&tc->tco, rec, len)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting "
				"and retrying in %d seconds\n",
			tc->name, SHORT_RETRY_WAIT_TIME);
		tconn_connect_one_disconnect(&tc->tco);
		schedule_retry(tc, SHORT_RETRY_WAIT_TIME);
	}
}
