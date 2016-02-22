/*
 * dvpn, a multipoint vpn implementation
 * Copyright (C) 2016 Lennert Buytenhek
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
#include <netinet/in.h>
#include <string.h>
#include "dgp_connect.h"
#include "util.h"

#define STATE_CONNECTING	1
#define STATE_ESTABLISHED	2
#define STATE_WAITING_RETRY	3

static void io_error(struct dgp_connect *dc)
{
	iv_fd_unregister(&dc->fd);
	close(dc->fd.fd);
	dgp_writer_unregister(&dc->dw);
	dgp_reader_unregister(&dc->dr);

	dc->state = STATE_WAITING_RETRY;

	iv_validate_now();
	dc->timeout.expires = iv_now;
	dc->timeout.expires.tv_sec += 1;
	iv_timer_register(&dc->timeout);
}

static void handle_dgp_read(void *_dc)
{
	struct dgp_connect *dc = _dc;

	if (dgp_reader_read(&dc->dr, dc->fd.fd) < 0)
		io_error(dc);
}

static void connect_success(struct dgp_connect *dc, int fd)
{
	dc->state = STATE_ESTABLISHED;

	iv_timer_unregister(&dc->timeout);

	iv_fd_set_handler_in(&dc->fd, handle_dgp_read);
	iv_fd_set_handler_out(&dc->fd, NULL);

	dgp_reader_register(&dc->dr);

	dc->dw.fd = dc->fd.fd;
	dgp_writer_register(&dc->dw);
}

static void connect_pollout(void *_dc)
{
	struct dgp_connect *dc = _dc;
	int fd;
	socklen_t len;
	int ret;

	fd = dc->fd.fd;

	len = sizeof(ret);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		perror("getsockopt");
		return;
	}

	if (ret == EINPROGRESS)
		return;

	if (ret == 0) {
		connect_success(dc, fd);
	} else {
		fprintf(stderr, "connect: %s\n", strerror(ret));

		iv_fd_unregister(&dc->fd);
		close(fd);

		dc->state = STATE_WAITING_RETRY;

		iv_timer_unregister(&dc->timeout);
		iv_validate_now();
		dc->timeout.expires = iv_now;
		dc->timeout.expires.tv_sec += 1;
		iv_timer_register(&dc->timeout);
	}
}

static void try_connect(struct dgp_connect *dc)
{
	int fd;
	uint8_t addr[16];
	struct sockaddr_in6 saddr;
	int ret;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto fail;
	}

	if (dc->myid != NULL) {
		if (!dc->ifindex)
			v6_global_addr_from_key_id(addr, dc->myid);
		else
			v6_linklocal_addr_from_key_id(addr, dc->myid);

		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = htons(44461);
		saddr.sin6_flowinfo = 0;
		memcpy(&saddr.sin6_addr, addr, 16);
		saddr.sin6_scope_id = dc->ifindex;

		if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
			perror("bind");
			close(fd);
			goto fail;
		}
	}

	dc->fd.fd = fd;
	dc->fd.handler_in = NULL;
	dc->fd.handler_out = connect_pollout;
	iv_fd_register(&dc->fd);

	if (!dc->ifindex)
		v6_global_addr_from_key_id(addr, dc->remoteid);
	else
		v6_linklocal_addr_from_key_id(addr, dc->remoteid);

	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(44461);
	saddr.sin6_flowinfo = 0;
	memcpy(&saddr.sin6_addr, addr, 16);
	saddr.sin6_scope_id = dc->ifindex;

	ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0 && errno != EINPROGRESS) {
		perror("connect");
		iv_fd_unregister(&dc->fd);
		close(fd);
		goto fail;
	}

	if (ret == 0) {
		connect_success(dc, fd);
	} else {
		iv_validate_now();
		dc->timeout.expires = iv_now;
		dc->timeout.expires.tv_sec += 10;
		iv_timer_register(&dc->timeout);
	}

	return;

fail:
	dc->state = STATE_WAITING_RETRY;

	iv_validate_now();
	dc->timeout.expires = iv_now;
	dc->timeout.expires.tv_sec += 1;
	iv_timer_register(&dc->timeout);
}

static void rx_timeout_expired(void *_dc)
{
	struct dgp_connect *dc = _dc;

	if (dc->state == STATE_CONNECTING) {
		iv_fd_unregister(&dc->fd);
		close(dc->fd.fd);

		dc->state = STATE_WAITING_RETRY;

		iv_validate_now();
		dc->timeout.expires = iv_now;
		dc->timeout.expires.tv_sec += 1;
		iv_timer_register(&dc->timeout);
	} else if (dc->state == STATE_WAITING_RETRY) {
		dc->state = STATE_CONNECTING;
		try_connect(dc);
	}
}

static void dr_dw_io_error(void *_dc)
{
	struct dgp_connect *dc = _dc;

	io_error(dc);
}

void dgp_connect_start(struct dgp_connect *dc)
{
	dc->state = STATE_CONNECTING;

	IV_TIMER_INIT(&dc->timeout);
	dc->timeout.cookie = dc;
	dc->timeout.handler = rx_timeout_expired;

	IV_FD_INIT(&dc->fd);
	dc->fd.cookie = dc;

	dc->dr.myid = dc->myid;
	dc->dr.remoteid = dc->remoteid;
	dc->dr.rib = dc->loc_rib;
	dc->dr.cookie = dc;
	dc->dr.io_error = dr_dw_io_error;

	dc->dw.myid = dc->myid;
	dc->dw.remoteid = dc->remoteid;
	dc->dw.rib = dc->loc_rib;
	dc->dw.cookie = dc;
	dc->dw.io_error = dr_dw_io_error;

	try_connect(dc);
}

void dgp_connect_stop(struct dgp_connect *dc)
{
	if (dc->state != STATE_ESTABLISHED)
		iv_timer_unregister(&dc->timeout);

	if (dc->state != STATE_WAITING_RETRY) {
		iv_fd_unregister(&dc->fd);
		close(dc->fd.fd);
	}

	if (dc->state == STATE_ESTABLISHED) {
		dgp_writer_unregister(&dc->dw);
		dgp_reader_unregister(&dc->dr);
	}
}
