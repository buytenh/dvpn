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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <netinet/tcp.h>
#include <string.h>
#include "conf.h"
#include "itf.h"
#include "listen.h"
#include "pconn.h"
#include "tun.h"
#include "util.h"
#include "x509.h"

struct client_conn
{
	struct listening_socket	*ls;
	struct listen_entry	*le;

	int			state;
	struct iv_timer		rx_timeout;
	struct pconn		pconn;
	struct iv_timer		keepalive_timer;
};

#define STATE_HANDSHAKE		1
#define STATE_CONNECTED		2

#define HANDSHAKE_TIMEOUT	30
#define KEEPALIVE_INTERVAL	30

static void client_conn_kill(struct client_conn *cc)
{
	if (cc->le != NULL) {
		if (cc->state == STATE_CONNECTED) {
			cc->le->set_state(cc->le->cookie, 0);
			itf_set_state(tun_interface_get_name(&cc->le->tun), 0);
		}
		cc->le->current = NULL;
	}

	if (iv_timer_registered(&cc->rx_timeout))
		iv_timer_unregister(&cc->rx_timeout);

	pconn_destroy(&cc->pconn);
	close(cc->pconn.fd);

	if (iv_timer_registered(&cc->keepalive_timer))
		iv_timer_unregister(&cc->keepalive_timer);

	free(cc);
}

static void print_name(FILE *fp, struct client_conn *cc)
{
	if (cc->le != NULL)
		fprintf(fp, "%s", cc->le->name);
	else
		fprintf(fp, "conn%d", cc->pconn.fd);
}

static void rx_timeout(void *_cc)
{
	struct client_conn *cc = _cc;

	print_name(stderr, cc);
	fprintf(stderr, ": receive timeout\n");

	client_conn_kill(cc);
}

static int verify_key_id(void *_cc, const uint8_t *id, int len)
{
	struct client_conn *cc = _cc;
	struct iv_list_head *lh;

	fprintf(stderr, "conn%d: peer key ID ", cc->pconn.fd);
	printhex(stderr, id, len);

	iv_list_for_each (lh, &cc->ls->listen_entries) {
		struct listen_entry *le;

		le = iv_list_entry(lh, struct listen_entry, list);
		if (!memcmp(le->fingerprint, id, 32)) {
			fprintf(stderr, " - matches '%s'\n", le->name);
			cc->le = le;
			return 0;
		}
	}

	fprintf(stderr, " - no matches\n");

	return 1;
}

static void handshake_done(void *_cc, char *desc)
{
	struct client_conn *cc = _cc;
	struct listen_entry *le = cc->le;
	int i;
	socklen_t len;
	uint8_t id[32];
	uint8_t addr[16];

	if (le->current != NULL) {
		fprintf(stderr, "%s: handshake done, using %s, disconnecting "
				"previous client\n", le->name, desc);
		client_conn_kill(le->current);
	} else {
		fprintf(stderr, "%s: handshake done, using %s\n",
			le->name, desc);
	}

	le->current = cc;

	i = 1;
	if (setsockopt(cc->pconn.fd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt(SOL_TCP, TCP_NODELAY)");
		abort();
	}

	len = sizeof(i);
	if (getsockopt(cc->pconn.fd, SOL_TCP, TCP_MAXSEG, &i, &len) < 0) {
		perror("getsockopt(SOL_TCP, TCP_MAXSEG)");
		abort();
	}

	i -= 5 + 8 + 3 + 16;
	if (i < 1280)
		i = 1280;
	else if (i > 1500)
		i = 1500;

	fprintf(stderr, "%s: setting interface MTU to %d\n", cc->le->name, i);
	itf_set_mtu(tun_interface_get_name(&le->tun), i);

	cc->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->rx_timeout);

	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	itf_set_state(tun_interface_get_name(&le->tun), 1);

	x509_get_key_id(id, sizeof(id), cc->ls->key);

	v6_linklocal_addr_from_key_id(addr, id, sizeof(id));
	itf_add_addr_v6(tun_interface_get_name(&le->tun), id, 10);

	v6_global_addr_from_key_id(addr, id, sizeof(id));
	if (le->peer_type != PEER_TYPE_TRANSIT) {
		itf_add_addr_v6(tun_interface_get_name(&le->tun), addr, 128);

		v6_global_addr_from_key_id(addr, le->fingerprint,
					   sizeof(le->fingerprint));
		itf_add_route_v6(tun_interface_get_name(&le->tun), addr, 128);
	} else {
		itf_add_addr_v6(tun_interface_get_name(&le->tun), addr, 32);
	}

	cc->le->set_state(cc->le->cookie, 1);
}

static void record_received(void *_cc, const uint8_t *rec, int len)
{
	struct client_conn *cc = _cc;
	int rlen;

	iv_validate_now();

	iv_timer_unregister(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->rx_timeout);

	if (len <= 3)
		return;

	if (rec[0] != 0x00)
		return;

	rlen = (rec[1] << 8) | rec[2];
	if (rlen + 3 != len)
		return;

	if (tun_interface_send_packet(&cc->le->tun, rec + 3, rlen) < 0) {
		fprintf(stderr, "%s: error forwarding received packet "
				"to tun interface, disconnecting\n", 
			cc->le->name);
		client_conn_kill(cc);
	}
}

static void connection_lost(void *_cc)
{
	struct client_conn *cc = _cc;

	print_name(stderr, cc);
	fprintf(stderr, ": connection lost\n");

	client_conn_kill(cc);
}

static void send_keepalive(void *_cc)
{
	static uint8_t keepalive[] = { 0x00, 0x00, 0x00 };
	struct client_conn *cc = _cc;

	if (pconn_record_send(&cc->pconn, keepalive, 3)) {
		fprintf(stderr, "%s: error sending keepalive, disconnecting\n", 
			cc->le->name);
		client_conn_kill(cc);
		return;
	}

	iv_validate_now();

	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);
}

static void got_connection(void *_ls)
{
	struct listening_socket *ls = _ls;
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

	cc->ls = ls;
	cc->le = NULL;

	cc->state = STATE_HANDSHAKE;

	iv_validate_now();

	IV_TIMER_INIT(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += HANDSHAKE_TIMEOUT;
	cc->rx_timeout.cookie = cc;
	cc->rx_timeout.handler = rx_timeout;
	iv_timer_register(&cc->rx_timeout);

	cc->pconn.fd = fd;
	cc->pconn.role = PCONN_ROLE_SERVER;
	cc->pconn.key = ls->key;
	cc->pconn.cookie = cc;
	cc->pconn.verify_key_id = verify_key_id;
	cc->pconn.handshake_done = handshake_done;
	cc->pconn.record_received = record_received;
	cc->pconn.connection_lost = connection_lost;

	IV_TIMER_INIT(&cc->keepalive_timer);
	cc->keepalive_timer.cookie = cc;
	cc->keepalive_timer.handler = send_keepalive;

	pconn_start(&cc->pconn);
}

static void got_packet(void *_le, uint8_t *buf, int len)
{
	struct listen_entry *le = _le;
	struct client_conn *cc;
	uint8_t sndbuf[len + 3];

	cc = le->current;
	if (cc == NULL)
		return;

	iv_validate_now();

	iv_timer_unregister(&cc->keepalive_timer);
	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	sndbuf[0] = 0x00;
	sndbuf[1] = len >> 8;
	sndbuf[2] = len & 0xff;
	memcpy(sndbuf + 3, buf, len);

	if (pconn_record_send(&cc->pconn, sndbuf, len + 3)) {
		fprintf(stderr, "%s: error sending TLS record, disconnecting\n",
			cc->le->name);
		client_conn_kill(cc);
	}
}

int listening_socket_register(struct listening_socket *ls)
{
	int fd;
	int yes;

	fd = socket(ls->listen_address.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("listening_socket_add: socket");
		return 1;
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("listening_socket_add: setsockopt");
		close(fd);
		return 1;
	}

	if (bind(fd, (struct sockaddr *)&ls->listen_address,
		 sizeof(ls->listen_address)) < 0) {
		perror("listening_socket_add: bind");
		close(fd);
		return 1;
	}

	if (listen(fd, 100) < 0) {
		perror("listening_socket_add: listen");
		close(fd);
		return 1;
	}

	IV_FD_INIT(&ls->listen_fd);
	ls->listen_fd.fd = fd;
	ls->listen_fd.cookie = ls;
	ls->listen_fd.handler_in = got_connection;
	iv_fd_register(&ls->listen_fd);

	INIT_IV_LIST_HEAD(&ls->listen_entries);

	return 0;
}

void listening_socket_unregister(struct listening_socket *ls)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	iv_fd_unregister(&ls->listen_fd);
	close(ls->listen_fd.fd);

	iv_list_for_each_safe (lh, lh2, &ls->listen_entries) {
		struct listen_entry *le;

		le = iv_list_entry(lh, struct listen_entry, list);
		listen_entry_unregister(le);
	}
}

int listen_entry_register(struct listen_entry *le)
{
	le->tun.itfname = le->tunitf;
	le->tun.cookie = le;
	le->tun.got_packet = got_packet;
	if (tun_interface_register(&le->tun) < 0)
		return 1;

	iv_list_add_tail(&le->list, &le->ls->listen_entries);

	itf_set_state(tun_interface_get_name(&le->tun), 0);

	le->current = NULL;

	return 0;
}

void listen_entry_unregister(struct listen_entry *le)
{
	if (le->current != NULL)
		client_conn_kill(le->current);

	iv_list_del(&le->list);
	tun_interface_unregister(&le->tun);
}
