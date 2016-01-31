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
#include <string.h>
#include "dgp_listen.h"

struct conn {
	struct dgp_listen_entry		*dle;

	struct iv_fd			fd;
	struct dgp_reader		dr;
	struct dgp_writer		dw;
};

static struct dgp_listen_entry *
find_entry_by_addr(struct dgp_listen_socket *dls, uint8_t *addr)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &dls->listen_entries) {
		struct dgp_listen_entry *dle;
		uint8_t a[16];

		dle = iv_container_of(lh, struct dgp_listen_entry, list);

		v6_global_addr_from_key_id(a, dle->remoteid, NODE_ID_LEN);
		if (!memcmp(addr, a, 16))
			return dle;
	}

	return NULL;
}

static void conn_kill(struct conn *conn)
{
	conn->dle->current = NULL;

	iv_fd_unregister(&conn->fd);
	close(conn->fd.fd);

	dgp_writer_unregister(&conn->dw);
	dgp_reader_unregister(&conn->dr);

	free(conn);
}

static void handle_dgp_read(void *_conn)
{
	struct conn *conn = _conn;

	if (dgp_reader_read(&conn->dr, conn->fd.fd) < 0)
		conn_kill(conn);
}

static void dw_io_error(void *_conn)
{
	struct conn *conn = _conn;

	conn_kill(conn);
}

static void got_connection(void *_dls)
{
	struct dgp_listen_socket *dls = _dls;
	socklen_t addrlen;
	struct sockaddr_storage addr;
	int fd;
	struct sockaddr_in6 *addr6;
	struct dgp_listen_entry *dle;
	struct conn *conn;

	addrlen = sizeof(addr);

	fd = accept(dls->listen_fd.fd, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		perror("got_connection: accept");
		return;
	}

	if (addr.ss_family != AF_INET6) {
		close(fd);
		return;
	}
	addr6 = (struct sockaddr_in6 *)&addr;

	dle = find_entry_by_addr(dls, addr6->sin6_addr.s6_addr);
	if (dle == NULL) {
		close(fd);
		return;
	}

	conn = malloc(sizeof(*conn));
	if (conn == NULL) {
		close(fd);
		return;
	}

	if (dle->current != NULL)
		conn_kill(dle->current);
	dle->current = conn;

	conn->dle = dle;

	IV_FD_INIT(&conn->fd);
	conn->fd.fd = fd;
	conn->fd.cookie = conn;
	conn->fd.handler_in = handle_dgp_read;
	iv_fd_register(&conn->fd);

	conn->dr.myid = dls->myid;
	conn->dr.remoteid = dle->remoteid;
	conn->dr.rib = dls->loc_rib;
	dgp_reader_register(&conn->dr);

	conn->dw.fd = fd;
	conn->dw.myid = NULL;
	conn->dw.remoteid = dle->remoteid;
	conn->dw.rib = dls->loc_rib;
	conn->dw.cookie = conn;
	conn->dw.io_error = dw_io_error;
	dgp_writer_register(&conn->dw);
}

int dgp_listen_socket_register(struct dgp_listen_socket *dls)
{
	int fd;
	int yes;
	uint8_t addr[16];
	struct sockaddr_in6 saddr;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("listen_start: setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		close(fd);
		return 1;
	}
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &yes, sizeof(yes)) < 0) {
		perror("listen_start: setsockopt(SOL_IP, IP_FREEBIND)");
		close(fd);
		return 1;
	}

	v6_global_addr_from_key_id(addr, dls->myid, NODE_ID_LEN);

	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(44461);
	saddr.sin6_flowinfo = 0;
	memcpy(&saddr.sin6_addr, addr, 16);
	saddr.sin6_scope_id = 0;

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("listen_start: bind");
		close(fd);
		return 1;
	}

	if (listen(fd, 100) < 0) {
		perror("listen_start: listen");
		close(fd);
		return 1;
	}

	IV_FD_INIT(&dls->listen_fd);
	dls->listen_fd.fd = fd;
	dls->listen_fd.cookie = dls;
	dls->listen_fd.handler_in = got_connection;
	iv_fd_register(&dls->listen_fd);

	INIT_IV_LIST_HEAD(&dls->listen_entries);

	return 0;
}

void dgp_listen_socket_unregister(struct dgp_listen_socket *dls)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	iv_fd_unregister(&dls->listen_fd);
	close(dls->listen_fd.fd);

	iv_list_for_each_safe (lh, lh2, &dls->listen_entries) {
		struct dgp_listen_entry *dle;

		dle = iv_list_entry(lh, struct dgp_listen_entry, list);
		dgp_listen_entry_unregister(dle);
	}
}

void dgp_listen_entry_register(struct dgp_listen_entry *dle)
{
	iv_list_add_tail(&dle->list, &dle->dls->listen_entries);
        dle->current = NULL;
}

void dgp_listen_entry_unregister(struct dgp_listen_entry *dle)
{
	if (dle->current != NULL)
		conn_kill(dle->current);

	iv_list_del_init(&dle->list);
}
