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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <netinet/tcp.h>
#include <string.h>
#include "conf.h"
#include "itf.h"
#include "tconn.h"
#include "tconn_listen.h"
#include "util.h"
#include "x509.h"

struct client_conn {
	struct tconn_listen_socket	*tls;
	struct tconn_listen_entry	*tle;

	int			state;
	struct iv_timer		rx_timeout;
	struct iv_fd		fd;
	struct tconn		tconn;
	struct iv_timer		keepalive_timer;
};

#define STATE_TLS_HANDSHAKE	1
#define STATE_CONNECTED		2

#define HANDSHAKE_TIMEOUT	30
#define KEEPALIVE_INTERVAL	30

static void print_name(FILE *fp, struct client_conn *cc)
{
	if (cc->tle != NULL)
		fprintf(fp, "%s", cc->tle->name);
	else
		fprintf(fp, "conn%d", cc->fd.fd);
}

static void client_conn_kill(struct client_conn *cc, int notify)
{
	if (cc->tle != NULL) {
		if (cc->state == STATE_CONNECTED && notify)
			cc->tle->set_state(cc->tle->cookie, 0);
		cc->tle->current = NULL;
	}

	if (iv_timer_registered(&cc->rx_timeout))
		iv_timer_unregister(&cc->rx_timeout);

	tconn_destroy(&cc->tconn);
	iv_fd_unregister(&cc->fd);
	close(cc->fd.fd);

	if (cc->state == STATE_CONNECTED)
		iv_timer_unregister(&cc->keepalive_timer);

	free(cc);
}

static void rx_timeout(void *_cc)
{
	struct client_conn *cc = _cc;

	print_name(stderr, cc);
	fprintf(stderr, ": receive timeout\n");

	client_conn_kill(cc, 1);
}

static int verify_key_id(void *_cc, const uint8_t *id)
{
	struct client_conn *cc = _cc;
	struct iv_list_head *lh;

	fprintf(stderr, "conn%d: peer key ID ", cc->fd.fd);
	printhex(stderr, id, NODE_ID_LEN);

	iv_list_for_each (lh, &cc->tls->listen_entries) {
		struct tconn_listen_entry *le;

		le = iv_list_entry(lh, struct tconn_listen_entry, list);
		if (!memcmp(le->fingerprint, id, NODE_ID_LEN)) {
			fprintf(stderr, " - matches '%s'\n", le->name);
			cc->tle = le;
			return 0;
		}
	}

	fprintf(stderr, " - no matches\n");

	return 1;
}

static void send_keepalive(void *_cc)
{
	static uint8_t keepalive[] = { 0x00, 0x00, 0x00 };
	struct client_conn *cc = _cc;

	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	if (tconn_record_send(&cc->tconn, keepalive, 3)) {
		fprintf(stderr, "%s: error sending keepalive, disconnecting\n", 
			cc->tle->name);
		client_conn_kill(cc, 1);
	}
}

static void handshake_done(void *_cc, char *desc)
{
	struct client_conn *cc = _cc;
	struct tconn_listen_entry *le = cc->tle;
	int i;

	if (le->current != NULL) {
		fprintf(stderr, "%s: handshake done, using %s, disconnecting "
				"previous client\n", le->name, desc);
		client_conn_kill(le->current, 1);
	} else {
		fprintf(stderr, "%s: handshake done, using %s\n",
			le->name, desc);
	}

	le->current = cc;

	i = 1;
	if (setsockopt(cc->fd.fd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt(SOL_TCP, TCP_NODELAY)");
		abort();
	}

	cc->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->rx_timeout);

	IV_TIMER_INIT(&cc->keepalive_timer);
	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	cc->keepalive_timer.cookie = cc;
	cc->keepalive_timer.handler = send_keepalive;
	iv_timer_register(&cc->keepalive_timer);

	cc->tle->set_state(cc->tle->cookie, 1);
}

static void record_received(void *_cc, const uint8_t *rec, int len)
{
	struct client_conn *cc = _cc;
	struct tconn_listen_entry *tle = cc->tle;

	iv_validate_now();

	iv_timer_unregister(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->rx_timeout);

	tle->record_received(tle->cookie, rec, len);
}

static void connection_lost(void *_cc)
{
	struct client_conn *cc = _cc;

	print_name(stderr, cc);
	fprintf(stderr, ": connection lost\n");

	client_conn_kill(cc, 1);
}

static void got_connection(void *_ls)
{
	struct tconn_listen_socket *ls = _ls;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd;
	struct client_conn *cc;

	addrlen = sizeof(addr);

	fd = accept(ls->listen_fd.fd, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		perror("got_connection: accept");
		return;
	}

	cc = malloc(sizeof(*cc));
	if (cc == NULL) {
		fprintf(stderr, "error allocating memory for cc object\n");
		close(fd);
		return;
	}

	fprintf(stderr, "conn%d: incoming connection from ", fd);
	print_address(stderr, (struct sockaddr *)&addr);
	fprintf(stderr, " to ");
	print_address(stderr, (struct sockaddr *)&ls->listen_address);
	fprintf(stderr, "\n");

	cc->tls = ls;
	cc->tle = NULL;

	cc->state = STATE_TLS_HANDSHAKE;

	iv_validate_now();

	IV_TIMER_INIT(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;
	cc->rx_timeout.cookie = cc;
	cc->rx_timeout.handler = rx_timeout;
	iv_timer_register(&cc->rx_timeout);

	IV_FD_INIT(&cc->fd);
	cc->fd.fd = fd;
	iv_fd_register(&cc->fd);

	cc->tconn.fd = &cc->fd;
	cc->tconn.role = TCONN_ROLE_SERVER;
	cc->tconn.key = ls->key;
	cc->tconn.cookie = cc;
	cc->tconn.verify_key_id = verify_key_id;
	cc->tconn.handshake_done = handshake_done;
	cc->tconn.record_received = record_received;
	cc->tconn.connection_lost = connection_lost;
	tconn_start(&cc->tconn);
}

int tconn_listen_socket_register(struct tconn_listen_socket *tls)
{
	int fd;
	int yes;

	fd = socket(tls->listen_address.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("tconn_listen_socket: socket");
		return 1;
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("tconn_listen_socket: setsockopt");
		close(fd);
		return 1;
	}

	if (bind(fd, (struct sockaddr *)&tls->listen_address,
		 sizeof(tls->listen_address)) < 0) {
		perror("tconn_listen_socket: bind");
		close(fd);
		return 1;
	}

	if (listen(fd, 100) < 0) {
		perror("tconn_listen_socket: listen");
		close(fd);
		return 1;
	}

	IV_FD_INIT(&tls->listen_fd);
	tls->listen_fd.fd = fd;
	tls->listen_fd.cookie = tls;
	tls->listen_fd.handler_in = got_connection;
	iv_fd_register(&tls->listen_fd);

	INIT_IV_LIST_HEAD(&tls->listen_entries);

	return 0;
}

void tconn_listen_socket_unregister(struct tconn_listen_socket *tls)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	iv_fd_unregister(&tls->listen_fd);
	close(tls->listen_fd.fd);

	iv_list_for_each_safe (lh, lh2, &tls->listen_entries) {
		struct tconn_listen_entry *le;

		le = iv_list_entry(lh, struct tconn_listen_entry, list);
		tconn_listen_entry_unregister(le);
	}
}

void tconn_listen_entry_register(struct tconn_listen_entry *tle)
{
	iv_list_add_tail(&tle->list, &tle->tls->listen_entries);

	tle->current = NULL;
}

void tconn_listen_entry_unregister(struct tconn_listen_entry *tle)
{
	if (tle->current != NULL)
		client_conn_kill(tle->current, 0);

	iv_list_del(&tle->list);
}

int tconn_listen_entry_get_maxseg(struct tconn_listen_entry *tle)
{
	struct client_conn *cc;
	int mseg;
	socklen_t len;

	cc = tle->current;
	if (cc == NULL)
		return -1;

	len = sizeof(mseg);
	if (getsockopt(cc->fd.fd, SOL_TCP, TCP_MAXSEG, &mseg, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_MAXSEG)");
		return -1;
	}

	return mseg;
}

void tconn_listen_entry_record_send(struct tconn_listen_entry *tle,
				    const uint8_t *rec, int len)
{
	struct client_conn *cc;

	cc = tle->current;
	if (cc == NULL)
		return;

	iv_validate_now();

	iv_timer_unregister(&cc->keepalive_timer);
	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	if (tconn_record_send(&cc->tconn, rec, len)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting\n",
			tle->name);
		client_conn_kill(cc, 1);
	}
}
