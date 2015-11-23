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
 * - smarter receive buffering
 *   - use a global pconn unregister counter and keep pulling records
 *     out of the rx buffer as long as this number stays the same
 * - smarter tx buffering, coalesce multiple packets into one sendto()?
 * - certificate caching
 * - use state validation functions to enforce all state machine transitions
 * - byte/time limits, renegotiation
 *   - work out state machine for renegotiation
 *   - limit min (limit at which we'll accept a remote reneg)
 *   - limit soft (initiate a reneg at this point)
 *   - limit hard (close the connection if this limit is exceeded)
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

static int verify_state_pollin(struct pconn *pc)
{
	/*
	 * Don't read after we've seen an I/O error.
	 */
	if (pc->state == STATE_DEAD || pc->io_error)
		return 0;

	/*
	 * Don't read if our input buffer contains data or if we've
	 * seen EOF.
	 */
	if (pc->rx_start != pc->rx_end || pc->rx_eof)
		return 0;

	return 1;
}

static int verify_state_pollout(struct pconn *pc)
{
	/*
	 * Don't write after we've seen an I/O error.
	 */
	if (pc->state == STATE_DEAD || pc->io_error)
		return 0;

	/*
	 * Don't write if there is nothing to send.
	 */
	if (!pc->tx_bytes)
		return 0;

	/*
	 * We shouldn't schedule POLLOUT until we have seen a partial
	 * write (or EAGAIN) on this socket, but we don't keep track of
	 * having seen partial writes, so we will sometimes get false
	 * positive errors here, where verify_state() will complain that
	 * a POLLOUT handler should be registered while there isn't, and
	 * the reason for that being that we haven't seen a partial
	 * write yet.
	 */

	return 1;
}

static int verify_state_rx_task(struct pconn *pc)
{
	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 0 &&
	    (pc->io_error || pc->rx_start != pc->rx_end || pc->rx_eof)) {
		return 1;
	}

	if ((pc->state == STATE_RUNNING || pc->state == STATE_TX_CONGESTION) &&
	    (gnutls_record_check_pending(pc->sess) || pc->io_error ||
	     pc->rx_start != pc->rx_end || pc->rx_eof)) {
		return 1;
	}

	return 0;
}

static int verify_state_tx_task(struct pconn *pc)
{
	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 1 &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		return 1;
	}

	if (pc->state == STATE_TX_CONGESTION &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		return 1;
	}

	return 0;
}

static void verify_state(struct pconn *pc)
{
	int st;

	st = verify_state_pollin(pc);
	if (!st && pc->ifd.handler_in != NULL) {
		fprintf(stderr, "error: handler_in should be NULL\n");
		abort();
	} else if (st && pc->ifd.handler_in == NULL) {
		fprintf(stderr, "error: handler_in is unexpectedly NULL\n");
		abort();
	}

	st = verify_state_pollout(pc);
	if (!st && pc->ifd.handler_out != NULL) {
		fprintf(stderr, "error: handler_out should be NULL\n");
		abort();
	} else if (st && pc->ifd.handler_out == NULL) {
		fprintf(stderr, "warning: handler_out is unexpectedly NULL\n");
	}

	st = verify_state_rx_task(pc);
	if (!st && iv_task_registered(&pc->rx_task)) {
		fprintf(stderr, "error: rx_task is unexpectedly registered\n");
		abort();
	} else if (st && !iv_task_registered(&pc->rx_task)) {
		fprintf(stderr, "error: rx_task should be registered\n");
		// => OR RUNNING (i.e. it's fine if we are in the middle of it)
		abort();
	}

	st = verify_state_tx_task(pc);
	if (!st && iv_task_registered(&pc->tx_task)) {
		fprintf(stderr, "error: tx_task is unexpectedly registered\n");
		abort();
	} else if (st && !iv_task_registered(&pc->tx_task)) {
		fprintf(stderr, "error: tx_task should be registered\n");
		abort();
	}
}

static void got_io_error(struct pconn *pc)
{
	iv_fd_set_handler_in(&pc->ifd, NULL);
	iv_fd_set_handler_out(&pc->ifd, NULL);

	if (!iv_task_registered(&pc->rx_task) &&
	    ((pc->state == STATE_HANDSHAKE &&
	      gnutls_record_get_direction(pc->sess) == 0) ||
	     pc->state == STATE_RUNNING ||
	     pc->state == STATE_TX_CONGESTION)) {
		iv_task_register(&pc->rx_task);
	}

	if (!iv_task_registered(&pc->tx_task) &&
	    ((pc->state == STATE_HANDSHAKE &&
	      gnutls_record_get_direction(pc->sess) == 1) ||
	     pc->state == STATE_TX_CONGESTION)) {
		iv_task_register(&pc->tx_task);
	}
}

static void pconn_fd_handler_in(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	verify_state(pc);

	if (pc->rx_start != pc->rx_end)
		abort();

	pc->rx_start = 0;
	pc->rx_end = 0;

	do {
		ret = recv(pc->ifd.fd, pc->rx_buf, sizeof(pc->rx_buf), 0);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0) {
		if (ret == 0 || errno != EAGAIN) {
			if (ret < 0)
				pc->io_error = errno;
			else
				pc->rx_eof = 1;

			got_io_error(pc);
		}

		verify_state(pc);

		return;
	}

	iv_fd_set_handler_in(&pc->ifd, NULL);

	if ((pc->state == STATE_HANDSHAKE &&
	     gnutls_record_get_direction(pc->sess) == 0) ||
	    pc->state == STATE_RUNNING ||
	    pc->state == STATE_TX_CONGESTION) {
		iv_task_register(&pc->rx_task);
	}

	pc->rx_end = ret;

	verify_state(pc);
}

static ssize_t
pconn_gtls_pull_func(gnutls_transport_ptr_t _pc, void *buf, size_t len)
{
	struct pconn *pc = _pc;

	if (pc->io_error) {
		gnutls_transport_set_errno(pc->sess, pc->io_error);
		return -1;
	}

	if (pc->rx_start != pc->rx_end) {
		int tocopy;

		tocopy = pc->rx_end - pc->rx_start;
		if (tocopy > len)
			tocopy = len;

		memcpy(buf, pc->rx_buf + pc->rx_start, tocopy);

		pc->rx_start += tocopy;
		if (pc->rx_start == pc->rx_end)
			iv_fd_set_handler_in(&pc->ifd, pconn_fd_handler_in);

		return tocopy;
	}

	if (pc->rx_eof)
		return 0;

	gnutls_transport_set_errno(pc->sess, EAGAIN);

	return -1;
}

static void pconn_fd_handler_out(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	verify_state(pc);

	do {
		ret = send(pc->ifd.fd, pc->tx_buf, pc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno != EAGAIN) {
			pc->io_error = errno;
			got_io_error(pc);
		}

		verify_state(pc);

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

	verify_state(pc);
}

static ssize_t
pconn_gtls_push_func(gnutls_transport_ptr_t _pc, const void *buf, size_t len)
{
	struct pconn *pc = _pc;
	int copied;
	int tocopy;

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

	if (pc->ifd.handler_out == NULL && pc->tx_bytes == sizeof(pc->tx_buf)) {
		int ret;

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
			iv_fd_set_handler_out(&pc->ifd, pconn_fd_handler_out);

		if (len && pc->tx_bytes < sizeof(pc->tx_buf))
			goto again;
	}

	return copied;
}

static int pconn_tx_flush(struct pconn *pc)
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
			iv_fd_set_handler_out(&pc->ifd, pconn_fd_handler_out);
			return 0;
		}

		pc->io_error = errno;

		return 1;
	}

	pc->tx_bytes -= ret;
	if (pc->tx_bytes) {
		memmove(pc->tx_buf, pc->tx_buf + ret, pc->tx_bytes);
		iv_fd_set_handler_out(&pc->ifd, pconn_fd_handler_out);
	}

	return 0;
}

static void gtls_perror(const char *str, int error)
{
	fprintf(stderr, "%s: %s\n", str, gnutls_strerror(error));
}

static void pconn_connection_abort(struct pconn *pc, int notify_err)
{
	iv_fd_set_handler_in(&pc->ifd, NULL);
	iv_fd_set_handler_out(&pc->ifd, NULL);

	pc->state = STATE_DEAD;

	if (iv_task_registered(&pc->rx_task))
		iv_task_unregister(&pc->rx_task);

	if (iv_task_registered(&pc->tx_task))
		iv_task_unregister(&pc->tx_task);

	if (notify_err)
		pc->connection_lost(pc->cookie);
}

static int pconn_do_handshake(struct pconn *pc, int notify_err)
{
	int ret;

	ret = gnutls_handshake(pc->sess);
	if ((!ret || ret == GNUTLS_E_AGAIN) && pconn_tx_flush(pc))
		ret = gnutls_handshake(pc->sess);

	if (ret) {
		if (ret != GNUTLS_E_AGAIN) {
			gtls_perror("gnutls_handshake", ret);
			pconn_connection_abort(pc, notify_err);
			return -1;
		}
		verify_state(pc);
		return 0;
	}

	gnutls_record_disable_padding(pc->sess);

	pc->state = STATE_RUNNING;

	if (gnutls_record_check_pending(pc->sess) ||
	    pc->rx_start != pc->rx_end || pc->rx_eof)
		iv_task_register(&pc->rx_task);

	verify_state(pc);

	pc->handshake_done(pc->cookie);

	return 0;
}

static void pconn_do_record_recv(struct pconn *pc)
{
	uint8_t buf[32768];
	int ret;

	ret = gnutls_record_recv(pc->sess, buf, sizeof(buf));

	if (ret == GNUTLS_E_AGAIN) {
		verify_state(pc);
		return;
	}

	if ((ret < 0 && ret != GNUTLS_E_REHANDSHAKE) || ret == 0) {
		if (ret)
			gtls_perror("gnutls_record_recv", ret);
		pconn_connection_abort(pc, 1);
		return;
	}

	if (gnutls_record_check_pending(pc->sess) ||
	    pc->rx_start != pc->rx_end || pc->rx_eof)
		iv_task_register(&pc->rx_task);

	verify_state(pc);

	if (ret == GNUTLS_E_REHANDSHAKE) {
		fprintf(stderr, "received HelloRequest\n");
	} else {
		pc->record_received(pc->cookie, buf, ret);
	}
}

static void pconn_do_record_send(struct pconn *pc)
{
	int ret;

	ret = gnutls_record_send(pc->sess, NULL, 0);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && pconn_tx_flush(pc))
		ret = gnutls_record_send(pc->sess, NULL, 0);

	if (ret == GNUTLS_E_AGAIN) {
		verify_state(pc);
		return;
	}

	if (ret) {
		gtls_perror("gnutls_record_send", ret);
		pconn_connection_abort(pc, 1);
		return;
	}

	// @@@ handle fewer bytes having been sent than passed in

	if (pc->state == STATE_TX_CONGESTION) {
		pc->state = STATE_RUNNING;
		verify_state(pc);
	} else {
		fprintf(stderr, "handle_record_send: called in state %d\n",
			pc->state);
		pconn_connection_abort(pc, 1);
	}
}

static void pconn_rx_task_handler(void *_pc)
{
	struct pconn *pc = _pc;

	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 0 &&
	    (pc->io_error || pc->rx_start != pc->rx_end || pc->rx_eof)) {
		pconn_do_handshake(pc, 1);
		return;
	}

	if ((pc->state == STATE_RUNNING || pc->state == STATE_TX_CONGESTION) &&
	    (gnutls_record_check_pending(pc->sess) || pc->io_error ||
	     pc->rx_start != pc->rx_end || pc->rx_eof)) {
		pconn_do_record_recv(pc);
		return;
	}

	abort();
}

static void pconn_tx_task_handler(void *_pc)
{
	struct pconn *pc = _pc;

	if (pc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(pc->sess) == 1 &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		pconn_do_handshake(pc, 1);
		return;
	}

	if (pc->state == STATE_TX_CONGESTION &&
	    (pc->io_error || pc->tx_bytes < sizeof(pc->tx_buf))) {
		pconn_do_record_send(pc);
		return;
	}

	abort();
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
	 * - verify that key is different from our key
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

static int pconn_start_handshake(struct pconn *pc)
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

	ret = pconn_do_handshake(pc, 0);
	if (ret)
		goto err_free;

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
	gnutls_transport_set_pull_function(pc->sess, pconn_gtls_pull_func);
	gnutls_transport_set_push_function(pc->sess, pconn_gtls_push_func);

	IV_FD_INIT(&pc->ifd);
	pc->ifd.fd = pc->fd;
	pc->ifd.cookie = pc;
	pc->ifd.handler_in = pconn_fd_handler_in;
	iv_fd_register(&pc->ifd);

	pc->io_error = 0;

	IV_TASK_INIT(&pc->rx_task);
	pc->rx_task.cookie = pc;
	pc->rx_task.handler = pconn_rx_task_handler;
	pc->rx_start = 0;
	pc->rx_end = 0;
	pc->rx_eof = 0;

	IV_TASK_INIT(&pc->tx_task);
	pc->tx_task.cookie = pc;
	pc->tx_task.handler = pconn_tx_task_handler;
	pc->tx_bytes = 0;

	ret = pconn_start_handshake(pc);
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

	verify_state(pc);

	if (pc->state == STATE_TX_CONGESTION) {
		return 0;
	} else if (pc->state != STATE_RUNNING) {
		fprintf(stderr, "got packet in [%d]\n", pc->state);
		return -1;
	}

	ret = gnutls_record_send(pc->sess, record, len);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && pconn_tx_flush(pc))
		ret = gnutls_record_send(pc->sess, NULL, 0);

	if (ret < 0 && ret != GNUTLS_E_AGAIN) {
		gtls_perror("gnutls_record_send", ret);
		pconn_connection_abort(pc, 0);
		return -1;
	}

	if (ret == GNUTLS_E_AGAIN)
		pc->state = STATE_TX_CONGESTION;

	// @@@ handle fewer bytes having been sent than passed in

	verify_state(pc);

	return 0;
}

void pconn_destroy(struct pconn *pc)
{
	verify_state(pc);

	gnutls_deinit(pc->sess);

	gnutls_certificate_free_credentials(pc->cert);

	iv_fd_unregister(&pc->ifd);

	if (iv_task_registered(&pc->rx_task))
		iv_task_unregister(&pc->rx_task);

	if (iv_task_registered(&pc->tx_task))
		iv_task_unregister(&pc->tx_task);
}
