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
#include <string.h>
#include "conf.h"
#include "itf.h"
#include "pconn.h"
#include "tun.h"
#include "x509.h"

struct listening_socket
{
	struct conf_listening_socket	*cls;
	gnutls_x509_privkey_t		key;

	struct iv_fd	listen_fd;
};

struct listen_entry
{
	struct conf_listen_entry	*cle;

	struct tun_interface	tun;
	struct client_conn	*current;
};

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

#define HANDSHAKE_TIMEOUT	10
#define KEEPALIVE_INTERVAL	30

static void client_conn_kill(struct client_conn *cc)
{
	if (cc->le != NULL) {
		if (cc->state == STATE_CONNECTED)
			itf_set_state(tun_interface_get_name(&cc->le->tun), 0);
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

static void printhex(const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		printf("%.2x", a[i]);
		if (i < len - 1)
			printf(":");
	}
}

static int verify_key_id(void *_cc, const uint8_t *id, int len)
{
	struct client_conn *cc = _cc;
	struct iv_list_head *lh;

	printf("key id: ");
	printhex(id, len);
	printf("\n");

	iv_list_for_each (lh, &cc->ls->cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);
		if (!memcmp(cle->fingerprint, id, 20)) {
			cc->le = cle->userptr;
			return 0;
		}
	}

	return 1;
}

static void handshake_done(void *_cc)
{
	struct client_conn *cc = _cc;
	struct listen_entry *le = cc->le;
	uint8_t id[64];

	fprintf(stderr, "%p: handshake done\n", cc);

	if (le->current != NULL)
		client_conn_kill(le->current);
	le->current = cc;

	cc->state = STATE_CONNECTED;

	iv_validate_now();

	iv_timer_unregister(&cc->rx_timeout);
	cc->rx_timeout.expires = iv_now;
	cc->rx_timeout.expires.tv_sec += 1.5 * KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->rx_timeout);

	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	x509_get_key_id(id + 2, sizeof(id) - 2, cc->ls->key);

	id[0] = 0xfe;
	id[1] = 0x80;
	itf_add_v6(tun_interface_get_name(&le->tun), id, 10);

	itf_set_state(tun_interface_get_name(&le->tun), 1);
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

	if (len <= 2)
		return;

	rlen = (rec[0] << 8) | rec[1];
	if (rlen + 2 != len)
		return;

	if (tun_interface_send_packet(&cc->le->tun, rec + 2, rlen) < 0)
		client_conn_kill(cc);
}

static void connection_lost(void *_cc)
{
	struct client_conn *cc = _cc;

	fprintf(stderr, "%p: connection lost\n", cc);

	client_conn_kill(cc);
}

static void rx_timeout(void *_cc)
{
	struct client_conn *cc = _cc;

	fprintf(stderr, "%p: rx timeout\n", cc);

	client_conn_kill(cc);
}

static void send_keepalive(void *_cc)
{
	static uint8_t keepalive[] = { 0x00, 0x00 };
	struct client_conn *cc = _cc;

	fprintf(stderr, "%p: sending keepalive\n", cc);

	if (pconn_record_send(&cc->pconn, keepalive, 2)) {
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
		perror("accept");
		return;
	}

	cc = malloc(sizeof(*cc));
	if (cc == NULL) {
		close(fd);
		return;
	}

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
	uint8_t sndbuf[len + 2];

	cc = le->current;
	if (cc == NULL)
		return;

	iv_validate_now();

	iv_timer_unregister(&cc->keepalive_timer);
	cc->keepalive_timer.expires = iv_now;
	cc->keepalive_timer.expires.tv_sec += KEEPALIVE_INTERVAL;
	iv_timer_register(&cc->keepalive_timer);

	sndbuf[0] = len >> 8;
	sndbuf[1] = len & 0xff;
	memcpy(sndbuf + 2, buf, len);

	if (pconn_record_send(&cc->pconn, sndbuf, len + 2))
		client_conn_kill(cc);
}

void *listening_socket_add(struct conf_listening_socket *cls,
			   gnutls_x509_privkey_t key)
{
	struct listening_socket *ls;
	int fd;
	int yes;
	struct iv_list_head *lh;

	fd = socket(cls->listen_address.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return NULL;
	}

	if (bind(fd, (struct sockaddr *)&cls->listen_address,
		 sizeof(cls->listen_address)) < 0) {
		perror("bind");
		close(fd);
		return NULL;
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("setsockopt");
		close(fd);
		return NULL;
	}

	if (listen(fd, 100) < 0) {
		perror("listen");
		close(fd);
		return NULL;
	}

	ls = malloc(sizeof(*ls));
	if (ls == NULL)
		return NULL;

	ls->cls = cls;
	ls->key = key;

	IV_FD_INIT(&ls->listen_fd);
	ls->listen_fd.fd = fd;
	ls->listen_fd.cookie = ls;
	ls->listen_fd.handler_in = got_connection;
	iv_fd_register(&ls->listen_fd);

	iv_list_for_each (lh, &cls->listen_entries) {
		struct conf_listen_entry *cle;
		struct listen_entry *le;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);

		le = malloc(sizeof(*le));
		if (le == NULL) {
			iv_fd_unregister(&ls->listen_fd);
			close(ls->listen_fd.fd);
			return NULL;
		}

		cle->userptr = le;

		le->cle = cle;

		le->tun.itfname = cle->tunitf;
		le->tun.cookie = le;
		le->tun.got_packet = got_packet;
		if (tun_interface_register(&le->tun) < 0) {
			iv_fd_unregister(&ls->listen_fd);
			close(ls->listen_fd.fd);
			return NULL;
		}

		le->current = NULL;
	}

	return ls;
}

void listening_socket_del(void *_ls)
{
	struct listening_socket *ls = _ls;
	struct iv_list_head *lh;

	iv_fd_unregister(&ls->listen_fd);
	close(ls->listen_fd.fd);

	iv_list_for_each (lh, &ls->cls->listen_entries) {
		struct conf_listen_entry *cle;

		cle = iv_list_entry(lh, struct conf_listen_entry, list);

		if (cle->userptr != NULL) {
			struct listen_entry *le = cle->userptr;

			if (le->current != NULL)
				client_conn_kill(le->current);
			tun_interface_unregister(&le->tun);

			free(le);
		}
	}

	free(ls);
}
