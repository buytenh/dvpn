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
 * - proper flow control handling
 * - graceful connection shutdown
 * - work out state machine for shutdown and renegotiation
 * - add error passing to ->connection_lost()
 * - byte/time limits, renegotiation
 *   - limit min (limit at which we'll accept a remote reneg)
 *   - limit soft (initiate a reneg at this point)
 *   - limit hard (close the connection if this limit is exceeded)
 * - implement rx_start/rx_end to avoid memmoves
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <iv.h>
#include <string.h>
#include "pconn.h"
#include "x509.h"

#define STATE_HANDSHAKE		1
#define STATE_RUNNING		2
#define STATE_TX_CONGESTION	3
#define STATE_DEAD		4

static void pconn_pull(void *_pc);
static void pconn_push(void *_pc);

static void gtls_perror(const char *str, int error)
{
	fprintf(stderr, "%s: %s\n", str, gnutls_strerror(error));
}

static int pconn_flush_tx(struct pconn *pc)
{
	int ret;

	if (pc->io_error)
		return 1;

	if (pc->ifd.handler_out != NULL || pc->tx_bytes == 0)
		return 0;

	do {
		ret = send(pc->ifd.fd, pc->tx_buf, pc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN) {
			iv_fd_set_handler_out(&pc->ifd, pconn_push);
			return 0;
		}

		pc->io_error = errno;
		return 1;
	}

	pc->tx_bytes -= ret;
	if (pc->tx_bytes) {
		memmove(pc->tx_buf, pc->tx_buf + ret, pc->tx_bytes);
		iv_fd_set_handler_out(&pc->ifd, pconn_push);
	}

	return 0;
}

static void connection_abort(struct pconn *pc)
{
	iv_fd_set_handler_in(&pc->ifd, NULL);
	iv_fd_set_handler_out(&pc->ifd, NULL);

	pc->state = STATE_DEAD;

	if (iv_timer_registered(&pc->handshake_timeout))
		iv_timer_unregister(&pc->handshake_timeout);

	if (iv_task_registered(&pc->rx_task))
		iv_task_unregister(&pc->rx_task);

	if (iv_task_registered(&pc->tx_task))
		iv_task_unregister(&pc->tx_task);

	pc->connection_lost(pc);
}

static void do_handshake(struct pconn *pc)
{
	int ret;

	ret = gnutls_handshake(pc->sess);
	if ((!ret || ret == GNUTLS_E_AGAIN) && pconn_flush_tx(pc))
		ret = gnutls_handshake(pc->sess);

	if (ret) {
		if (ret != GNUTLS_E_AGAIN) {
			gtls_perror("gnutls_handshake", ret);
			connection_abort(pc);
		}
		return;
	}

	gnutls_record_disable_padding(pc->sess);

	pc->state = STATE_RUNNING;

	iv_timer_unregister(&pc->handshake_timeout);

	if (gnutls_record_check_pending(pc->sess) || pc->rx_bytes || pc->rx_eof)
		iv_task_register(&pc->rx_task);

	pc->handshake_done(pc->cookie);
}

static void do_record_recv(struct pconn *pc)
{
	uint8_t buf[32768];
	int ret;

	ret = gnutls_record_recv(pc->sess, buf, sizeof(buf));

	if (ret == GNUTLS_E_AGAIN)
		return;

	if (ret == GNUTLS_E_REHANDSHAKE) {
		fprintf(stderr, "received HelloRequest\n");
		iv_task_register(&pc->rx_task);
		return;
	}

	if (ret <= 0) {
		if (ret)
			gtls_perror("gnutls_record_recv", ret);
		connection_abort(pc);
		return;
	}

	if (gnutls_record_check_pending(pc->sess) || pc->rx_bytes || pc->rx_eof)
		iv_task_register(&pc->rx_task);

	pc->record_received(pc->cookie, buf, ret);
}

static void do_record_send(struct pconn *pc)
{
	int ret;

	ret = gnutls_record_send(pc->sess, NULL, 0);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && pconn_flush_tx(pc))
		ret = gnutls_record_send(pc->sess, NULL, 0);

	if (ret == GNUTLS_E_AGAIN)
		return;

	if (ret) {
		gtls_perror("gnutls_record_send", ret);
		connection_abort(pc);
		return;
	}

	// @@@ handle fewer bytes having been sent than passed in

	if (pc->state == STATE_TX_CONGESTION) {
		pc->state = STATE_RUNNING;
	} else {
		fprintf(stderr, "handle_record_send: called in state %d\n",
			pc->state);
		connection_abort(pc);
	}
}

static void rx_task_handler(void *_pc)
{
	struct pconn *pc = _pc;

	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 0 &&
	    (pc->io_error || pc->rx_bytes || pc->rx_eof)) {
		do_handshake(pc);
		return;
	}

	if ((pc->state == STATE_RUNNING || pc->state == STATE_TX_CONGESTION) &&
	    (gnutls_record_check_pending(pc->sess) || pc->io_error ||
	     pc->rx_bytes || pc->rx_eof)) {
		do_record_recv(pc);
		return;
	}

	abort();
}

static void tx_task_handler(void *_pc)
{
	struct pconn *pc = _pc;

	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 1 &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		do_handshake(pc);
		return;
	}

	if (pc->state == STATE_TX_CONGESTION &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		do_record_send(pc);
		return;
	}

	abort();
}

static void pconn_pull(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	do {
		ret = recv(pc->ifd.fd, pc->rx_buf + pc->rx_bytes,
				sizeof(pc->rx_buf) - pc->rx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0) {
		if (ret == 0 || errno != EAGAIN) {
			if (ret < 0)
				pc->io_error = errno;
			else
				pc->rx_eof = 1;

			iv_fd_set_handler_in(&pc->ifd, NULL);
			iv_fd_set_handler_out(&pc->ifd, NULL);

			if (!iv_task_registered(&pc->rx_task))
				iv_task_register(&pc->rx_task);

			if (!iv_task_registered(&pc->tx_task))
				iv_task_register(&pc->tx_task);
		}

		return;
	}

	if (!pc->rx_bytes) {
		if ((pc->state == STATE_HANDSHAKE &&
		     gnutls_record_get_direction(pc->sess) == 0) ||
		    pc->state == STATE_RUNNING ||
		    pc->state == STATE_TX_CONGESTION) {
			iv_task_register(&pc->rx_task);
		}
	}

	pc->rx_bytes += ret;
	if (pc->rx_bytes == sizeof(pc->rx_buf))
		iv_fd_set_handler_in(&pc->ifd, NULL);
}

static ssize_t
pconn_pull_func(gnutls_transport_ptr_t _pc, void *buf, size_t len)
{
	struct pconn *pc = _pc;

	if (pc->io_error) {
		gnutls_transport_set_errno(pc->sess, pc->io_error);
		return -1;
	}

	if (pc->rx_bytes) {
		int tocopy;

		if (pc->rx_bytes == sizeof(pc->rx_buf))
			iv_fd_set_handler_in(&pc->ifd, pconn_pull);

		tocopy = pc->rx_bytes;
		if (tocopy > len)
			tocopy = len;
		memcpy(buf, pc->rx_buf, tocopy);

		pc->rx_bytes -= tocopy;
		if (pc->rx_bytes)
			memmove(pc->rx_buf, pc->rx_buf + tocopy, pc->rx_bytes);

		// @@@ pull more data from socket if buffer was full?

		return tocopy;
	}

	if (pc->rx_eof)
		return 0;

	gnutls_transport_set_errno(pc->sess, EAGAIN);

	return -1;
}

static void pconn_push(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	do {
		ret = send(pc->ifd.fd, pc->tx_buf, pc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno != EAGAIN) {
			pc->io_error = errno;

			iv_fd_set_handler_in(&pc->ifd, NULL);
			iv_fd_set_handler_out(&pc->ifd, NULL);

			if (!iv_task_registered(&pc->rx_task))
				iv_task_register(&pc->rx_task);

			if (!iv_task_registered(&pc->tx_task))
				iv_task_register(&pc->tx_task);
		}

		return;
	}

	if (pc->tx_bytes == sizeof(pc->tx_buf)) {
		if ((pc->state == STATE_HANDSHAKE &&
		     gnutls_record_get_direction(pc->sess) == 1) ||
		    pc->state == STATE_TX_CONGESTION) {
			iv_task_register(&pc->tx_task);
		}
	}

	pc->tx_bytes -= ret;
	if (pc->tx_bytes)
		memmove(pc->tx_buf, pc->tx_buf + ret, pc->tx_bytes);
	else
		iv_fd_set_handler_out(&pc->ifd, NULL);
}

static ssize_t
pconn_push_func(gnutls_transport_ptr_t _pc, const void *buf, size_t len)
{
	struct pconn *pc = _pc;
	int copied;
	int tocopy;
	int ret;

	if (pc->io_error) {
		gnutls_transport_set_errno(pc->sess, pc->io_error);
		return -1;
	}

	if (pc->tx_bytes == sizeof(pc->tx_buf)) {
		gnutls_transport_set_errno(pc->sess, EAGAIN);
		return -1;
	}

	copied = 0;

again:
	tocopy = sizeof(pc->tx_buf) - pc->tx_bytes;
	if (tocopy > len)
		tocopy = len;

	memcpy(pc->tx_buf + pc->tx_bytes, buf, tocopy);
	pc->tx_bytes += tocopy;
	copied += tocopy;
	buf += tocopy;
	len -= tocopy;

	if (pc->ifd.handler_out != NULL || pc->tx_bytes < sizeof(pc->tx_buf))
		return copied;

	do {
		ret = send(pc->ifd.fd, pc->tx_buf, pc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 && errno != EAGAIN) {
		pc->io_error = errno;
		gnutls_transport_set_errno(pc->sess, errno);
		return -1;
	}

	if (ret > 0) {
		pc->tx_bytes -= ret;
		if (pc->tx_bytes) {
			memmove(pc->tx_buf, pc->tx_buf + ret,
				pc->tx_bytes);
		}
	}

	if (pc->tx_bytes)
		iv_fd_set_handler_out(&pc->ifd, pconn_push);

	if (len && pc->tx_bytes < sizeof(pc->tx_buf))
		goto again;

	return copied;
}

static int pconn_verify_cert(gnutls_session_t sess)
{
	struct pconn *pc = gnutls_transport_get_ptr(sess);
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	gnutls_x509_crt_t peercert;
	int ret;
	gnutls_pubkey_t peerkey;
	uint8_t buf[256];
	size_t len;

	/*
	 * TBD: @@@
	 * - verify key length
	 * - verify that certificate signature is correct
	 * - verify signature time validity
	 * - verify that signature corresponds to given public key
	 */

	cert_list = gnutls_certificate_get_peers(pc->sess, &cert_list_size);
	if (cert_list_size != 1) {
		fprintf(stderr, "pconn_verify_cert: unexpected cert count\n");
		goto err;
	}

	ret = gnutls_x509_crt_init(&peercert);
	if (ret) {
		gtls_perror("gnutls_x509_crt_init", ret);
		goto err;
	}

	ret = gnutls_x509_crt_import(peercert, &cert_list[0],
				     GNUTLS_X509_FMT_DER);
	if (ret) {
		gtls_perror("gnutls_x509_crt_import", ret);
		goto err_free_crt;
	}

	ret = gnutls_pubkey_init(&peerkey);
	if (ret) {
		gtls_perror("gnutls_pubkey_init", ret);
		goto err_free_crt;
	}

	ret = gnutls_pubkey_import_x509(peerkey, peercert, 0);
	if (ret) {
		gtls_perror("gnutls_pubkey_import_x509", ret);
		goto err_free_key;
	}

	len = sizeof(buf);
	ret = gnutls_pubkey_get_key_id(peerkey, 0, buf, &len);
	if (ret) {
		gtls_perror("gnutls_pubkey_get_key_id", ret);
		goto err_free_key;
	}

	if (0) {
		int i;

		fprintf(stderr, "%p: ", pc);
		for (i = 0; i < len; i++) {
			fprintf(stderr, "%.2x", buf[i]);
			if (i < len - 1)
				fprintf(stderr, ":");
		}
		fprintf(stderr, "\n");
	}

	if (0) {
		gnutls_datum_t cinfo;

		if (gnutls_x509_crt_print(peercert, GNUTLS_CRT_PRINT_FULL,
					  &cinfo) == 0) {
			printf("\t%s\n", cinfo.data);
			free(cinfo.data);
		}
	}

	gnutls_pubkey_deinit(peerkey);
	gnutls_x509_crt_deinit(peercert);

	return pc->verify_key_id(pc->cookie, buf, len);

err_free_key:
	gnutls_pubkey_deinit(peerkey);

err_free_crt:
	gnutls_x509_crt_deinit(peercert);

err:
	return 1;
}

static void handshake_timeout(void *_pc)
{
	struct pconn *pc = _pc;

	connection_abort(pc);
}

static int start_handshake(struct pconn *pc)
{
	int ret;
	gnutls_x509_crt_t cert;

	ret = gnutls_certificate_allocate_credentials(&pc->cert);
	if (ret) {
		gtls_perror("gnutls_certificate_allocate_credentials", ret);
		goto err;
	}

	gnutls_certificate_set_verify_function(pc->cert, pconn_verify_cert);

	ret = x509_generate_cert(&cert, pc->key);
	if (ret)
		goto err_free;

	ret = gnutls_certificate_set_x509_key(pc->cert, &cert, 1, pc->key);
	gnutls_x509_crt_deinit(cert);

	if (ret) {
		gtls_perror("gnutls_certificate_set_x509_key", ret);
		goto err_free;
	}

	ret = gnutls_credentials_set(pc->sess, GNUTLS_CRD_CERTIFICATE,
				     pc->cert);
	if (ret) {
		gtls_perror("gnutls_credentials_set", ret);
		goto err_free;
	}

	pc->state = STATE_HANDSHAKE;

	iv_validate_now();
	pc->handshake_timeout.expires = iv_now;
	pc->handshake_timeout.expires.tv_sec += 10;
	iv_timer_register(&pc->handshake_timeout);

	do_handshake(pc);

	return 0;

err_free:
	gnutls_certificate_free_credentials(pc->cert);

err:
	return -1;
}

int pconn_start(struct pconn *pc)
{
	static char prio[] =
		"NONE:+CIPHER-ALL:+ECDHE-RSA:+MAC-ALL:+COMP-NULL:"
		"+VERS-TLS1.2:+SIGN-ALL:+CURVE-SECP256R1:%SAFE_RENEGOTIATION";
	unsigned int flags;
	int ret;
	const char *err;

	flags = GNUTLS_NONBLOCK | GNUTLS_NO_EXTENSIONS;
	if (pc->role == PCONN_ROLE_SERVER)
		flags |= GNUTLS_SERVER;
	else
		flags |= GNUTLS_CLIENT;

	ret = gnutls_init(&pc->sess, flags);
	if (ret) {
		gtls_perror("gnutls_init", ret);
		goto err;
	}

	if (pc->role == PCONN_ROLE_SERVER) {
		gnutls_certificate_server_set_request(pc->sess,
						      GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(pc->sess, 1);
	}

	ret = gnutls_priority_set_direct(pc->sess, prio, &err);
	if (ret) {
		const char *p;

		gtls_perror("gnutls_priority_set_direct", ret);

		fprintf(stderr, "%s\n", prio);
		for (p = prio; p < err; p++)
			fprintf(stderr, " ");
		fprintf(stderr, "^ error in priority string\n");

		goto err_deinit;
	}

	gnutls_transport_set_ptr(pc->sess, pc);
	gnutls_transport_set_pull_function(pc->sess, pconn_pull_func);
	gnutls_transport_set_push_function(pc->sess, pconn_push_func);

	IV_FD_INIT(&pc->ifd);
	pc->ifd.fd = pc->fd;
	pc->ifd.cookie = pc;
	pc->ifd.handler_in = pconn_pull;
	iv_fd_register(&pc->ifd);

	IV_TIMER_INIT(&pc->handshake_timeout);
	pc->handshake_timeout.cookie = pc;
	pc->handshake_timeout.handler = handshake_timeout;

	pc->io_error = 0;

	IV_TASK_INIT(&pc->rx_task);
	pc->rx_task.cookie = pc;
	pc->rx_task.handler = rx_task_handler;
	pc->rx_bytes = 0;
	pc->rx_eof = 0;

	IV_TASK_INIT(&pc->tx_task);
	pc->tx_task.cookie = pc;
	pc->tx_task.handler = tx_task_handler;
	pc->tx_bytes = 0;

	ret = start_handshake(pc);
	if (ret)
		goto err_deinit;

	return 0;

err_deinit:
	gnutls_deinit(pc->sess);

err:
	return -1;
}

int pconn_record_send(struct pconn *pc, const uint8_t *record, int len)
{
	int ret;

	if (pc->state != STATE_RUNNING) {
		fprintf(stderr, "got packet in [%d]\n", pc->state);
		return -1;
	}

	ret = gnutls_record_send(pc->sess, record, len);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && pconn_flush_tx(pc))
		ret = gnutls_record_send(pc->sess, NULL, 0);

	if (ret == GNUTLS_E_AGAIN) {
		pc->state = STATE_TX_CONGESTION;
	} else if (ret < 0) {
		gtls_perror("gnutls_record_send", ret);
		connection_abort(pc);
	}

	// @@@ handle fewer bytes having been sent than passed in

	return 0;
}

void pconn_destroy(struct pconn *pc)
{
	gnutls_deinit(pc->sess);

	gnutls_certificate_free_credentials(pc->cert);

	iv_fd_unregister(&pc->ifd);

	if (iv_timer_registered(&pc->handshake_timeout))
		iv_timer_unregister(&pc->handshake_timeout);

	if (iv_task_registered(&pc->rx_task))
		iv_task_unregister(&pc->rx_task);

	if (iv_task_registered(&pc->tx_task))
		iv_task_unregister(&pc->tx_task);
}
