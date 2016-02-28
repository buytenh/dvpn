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
 * - certificate caching
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
#include <netinet/tcp.h>
#include <string.h>
#include "tconn.h"
#include "util.h"
#include "x509.h"

#define STATE_HANDSHAKE		1
#define STATE_RUNNING		2
#define STATE_TX_CONGESTION	3
#define STATE_DEAD		4

static int verify_state_pollin(struct tconn *tc)
{
	/*
	 * Don't read after we've seen an I/O error.
	 */
	if (tc->state == STATE_DEAD || tc->io_error)
		return 0;

	/*
	 * Don't read if our input buffer contains data or if we've
	 * seen EOF.
	 */
	if (tc->rx_start != tc->rx_end || tc->rx_eof)
		return 0;

	return 1;
}

static int verify_state_pollout(struct tconn *tc)
{
	/*
	 * Don't write after we've seen an I/O error.
	 */
	if (tc->state == STATE_DEAD || tc->io_error)
		return 0;

	/*
	 * Don't write if there is nothing to send.
	 */
	if (!tc->tx_bytes)
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

static int verify_state_rx_task(struct tconn *tc)
{
	if (tc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(tc->sess) == 0 &&
	    (tc->io_error || tc->rx_start != tc->rx_end || tc->rx_eof)) {
		return 1;
	}

	if ((tc->state == STATE_RUNNING || tc->state == STATE_TX_CONGESTION) &&
	    (gnutls_record_check_pending(tc->sess) || tc->io_error ||
	     tc->rx_start != tc->rx_end || tc->rx_eof)) {
		return 1;
	}

	return 0;
}

static int verify_state_tx_task(struct tconn *tc)
{
	if (tc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(tc->sess) == 1 &&
	    (tc->io_error || tc->tx_bytes < sizeof(tc->tx_buf))) {
		return 1;
	}

	if (tc->state == STATE_TX_CONGESTION &&
	    (tc->io_error || tc->tx_bytes < sizeof(tc->tx_buf))) {
		return 1;
	}

	return 0;
}

static void verify_state(struct tconn *tc)
{
	int st;

	st = verify_state_pollin(tc);
	if (!st && tc->fd->handler_in != NULL) {
		fprintf(stderr, "error: handler_in should be NULL\n");
		abort();
	} else if (st && tc->fd->handler_in == NULL) {
		fprintf(stderr, "error: handler_in is unexpectedly NULL\n");
		abort();
	}

	st = verify_state_pollout(tc);
	if (!st && tc->fd->handler_out != NULL) {
		fprintf(stderr, "error: handler_out should be NULL\n");
		abort();
	} else if (st && tc->fd->handler_out == NULL) {
		fprintf(stderr, "warning: handler_out is unexpectedly NULL\n");
	}

	st = verify_state_rx_task(tc);
	if (!st && iv_task_registered(&tc->rx_task)) {
		fprintf(stderr, "error: rx_task is unexpectedly registered\n");
		abort();
	} else if (st && !iv_task_registered(&tc->rx_task)) {
		fprintf(stderr, "error: rx_task should be registered\n");
		// => OR RUNNING (i.e. it's fine if we are in the middle of it)
		abort();
	}

	st = verify_state_tx_task(tc);
	if (!st && iv_task_registered(&tc->tx_task)) {
		fprintf(stderr, "error: tx_task is unexpectedly registered\n");
		abort();
	} else if (st && !iv_task_registered(&tc->tx_task)) {
		fprintf(stderr, "error: tx_task should be registered\n");
		abort();
	}
}

static void got_io_error(struct tconn *tc)
{
	iv_fd_set_handler_in(tc->fd, NULL);
	iv_fd_set_handler_out(tc->fd, NULL);

	if (!iv_task_registered(&tc->rx_task) &&
	    ((tc->state == STATE_HANDSHAKE &&
	      gnutls_record_get_direction(tc->sess) == 0) ||
	     tc->state == STATE_RUNNING ||
	     tc->state == STATE_TX_CONGESTION)) {
		iv_task_register(&tc->rx_task);
	}

	if (!iv_task_registered(&tc->tx_task) &&
	    ((tc->state == STATE_HANDSHAKE &&
	      gnutls_record_get_direction(tc->sess) == 1) ||
	     tc->state == STATE_TX_CONGESTION)) {
		iv_task_register(&tc->tx_task);
	}
}

static void tconn_fd_handler_in(void *_tc)
{
	struct tconn *tc = _tc;
	int ret;

	verify_state(tc);

	if (tc->rx_start != tc->rx_end)
		abort();

	tc->rx_start = 0;
	tc->rx_end = 0;

	do {
		ret = recv(tc->fd->fd, tc->rx_buf, sizeof(tc->rx_buf), 0);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0) {
		if (ret == 0 || errno != EAGAIN) {
			if (ret < 0)
				tc->io_error = errno;
			else
				tc->rx_eof = 1;

			got_io_error(tc);
		}

		verify_state(tc);

		return;
	}

	iv_fd_set_handler_in(tc->fd, NULL);

	if ((tc->state == STATE_HANDSHAKE &&
	     gnutls_record_get_direction(tc->sess) == 0) ||
	    tc->state == STATE_RUNNING ||
	    tc->state == STATE_TX_CONGESTION) {
		iv_task_register(&tc->rx_task);
	}

	tc->rx_end = ret;

	verify_state(tc);
}

static ssize_t
tconn_gtls_pull_func(gnutls_transport_ptr_t _tc, void *buf, size_t len)
{
	struct tconn *tc = _tc;

	if (tc->io_error) {
		gnutls_transport_set_errno(tc->sess, tc->io_error);
		return -1;
	}

	if (tc->rx_start != tc->rx_end) {
		int tocopy;

		tocopy = tc->rx_end - tc->rx_start;
		if (tocopy > len)
			tocopy = len;

		memcpy(buf, tc->rx_buf + tc->rx_start, tocopy);

		tc->rx_start += tocopy;
		if (tc->rx_start == tc->rx_end)
			iv_fd_set_handler_in(tc->fd, tconn_fd_handler_in);

		return tocopy;
	}

	if (tc->rx_eof)
		return 0;

	gnutls_transport_set_errno(tc->sess, EAGAIN);

	return -1;
}

static void tconn_fd_handler_out(void *_tc)
{
	struct tconn *tc = _tc;
	int ret;

	verify_state(tc);

	do {
		ret = send(tc->fd->fd, tc->tx_buf, tc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno != EAGAIN) {
			tc->io_error = errno;
			got_io_error(tc);
		}

		verify_state(tc);

		return;
	}

	if (tc->tx_bytes == sizeof(tc->tx_buf)) {
		if ((tc->state == STATE_HANDSHAKE &&
		     gnutls_record_get_direction(tc->sess) == 1) ||
		    tc->state == STATE_TX_CONGESTION) {
			iv_task_register(&tc->tx_task);
		}
	}

	tc->tx_bytes -= ret;
	if (tc->tx_bytes)
		memmove(tc->tx_buf, tc->tx_buf + ret, tc->tx_bytes);
	else
		iv_fd_set_handler_out(tc->fd, NULL);

	verify_state(tc);
}

static ssize_t
tconn_gtls_push_func(gnutls_transport_ptr_t _tc, const void *buf, size_t len)
{
	struct tconn *tc = _tc;
	int copied;
	int tocopy;

	if (tc->io_error) {
		gnutls_transport_set_errno(tc->sess, tc->io_error);
		return -1;
	}

	if (tc->tx_bytes == sizeof(tc->tx_buf)) {
		gnutls_transport_set_errno(tc->sess, EAGAIN);
		return -1;
	}

	copied = 0;

again:
	tocopy = sizeof(tc->tx_buf) - tc->tx_bytes;
	if (tocopy > len)
		tocopy = len;

	memcpy(tc->tx_buf + tc->tx_bytes, buf, tocopy);
	tc->tx_bytes += tocopy;
	copied += tocopy;
	buf += tocopy;
	len -= tocopy;

	if (tc->fd->handler_out == NULL && tc->tx_bytes == sizeof(tc->tx_buf)) {
		int ret;

		do {
			ret = send(tc->fd->fd, tc->tx_buf, tc->tx_bytes, 0);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0 && errno != EAGAIN) {
			tc->io_error = errno;
			gnutls_transport_set_errno(tc->sess, errno);
			return -1;
		}

		if (ret > 0) {
			tc->tx_bytes -= ret;
			if (tc->tx_bytes) {
				memmove(tc->tx_buf, tc->tx_buf + ret,
					tc->tx_bytes);
			}
		}

		if (tc->tx_bytes)
			iv_fd_set_handler_out(tc->fd, tconn_fd_handler_out);

		if (len && tc->tx_bytes < sizeof(tc->tx_buf))
			goto again;
	}

	return copied;
}

static int tconn_tx_flush(struct tconn *tc)
{
	int ret;

	if (tc->io_error)
		return 1;

	if (tc->fd->handler_out != NULL || tc->tx_bytes == 0)
		return 0;

	do {
		ret = send(tc->fd->fd, tc->tx_buf, tc->tx_bytes, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN) {
			iv_fd_set_handler_out(tc->fd, tconn_fd_handler_out);
			return 0;
		}

		tc->io_error = errno;

		return 1;
	}

	tc->tx_bytes -= ret;
	if (tc->tx_bytes) {
		memmove(tc->tx_buf, tc->tx_buf + ret, tc->tx_bytes);
		iv_fd_set_handler_out(tc->fd, tconn_fd_handler_out);
	}

	return 0;
}

static void gtls_perror(const char *str, int error)
{
	fprintf(stderr, "%s: %s\n", str, gnutls_strerror(error));
}

static void tconn_connection_abort(struct tconn *tc, int notify_err)
{
	iv_fd_set_handler_in(tc->fd, NULL);
	iv_fd_set_handler_out(tc->fd, NULL);

	tc->state = STATE_DEAD;

	if (iv_task_registered(&tc->rx_task))
		iv_task_unregister(&tc->rx_task);

	if (iv_task_registered(&tc->tx_task))
		iv_task_unregister(&tc->tx_task);

	if (notify_err)
		tc->connection_lost(tc->cookie);
}

static int tconn_do_handshake(struct tconn *tc, int notify_err)
{
	char *desc;
	int ret;
	int i;

	ret = gnutls_handshake(tc->sess);
	if ((!ret || ret == GNUTLS_E_AGAIN) && tconn_tx_flush(tc))
		ret = gnutls_handshake(tc->sess);

	if (ret) {
		if (ret != GNUTLS_E_AGAIN) {
			gtls_perror("gnutls_handshake", ret);
			tconn_connection_abort(tc, notify_err);
			return -1;
		}
		verify_state(tc);
		return 0;
	}

	gnutls_record_disable_padding(tc->sess);

	tc->state = STATE_RUNNING;

	if (gnutls_record_check_pending(tc->sess) ||
	    tc->rx_start != tc->rx_end || tc->rx_eof)
		iv_task_register(&tc->rx_task);

	verify_state(tc);

	i = 1;
	if (setsockopt(tc->fd->fd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt(SOL_TCP, TCP_NODELAY)");
		abort();
	}

	desc = gnutls_session_get_desc(tc->sess);
	tc->handshake_done(tc->cookie, desc);
	gnutls_free(desc);

	return 0;
}

static void tconn_do_record_recv(struct tconn *tc)
{
	uint8_t buf[32768];
	int ret;

	ret = gnutls_record_recv(tc->sess, buf, sizeof(buf));

	if (ret == GNUTLS_E_AGAIN) {
		verify_state(tc);
		return;
	}

	if ((ret < 0 && ret != GNUTLS_E_REHANDSHAKE) || ret == 0) {
		if (ret)
			gtls_perror("gnutls_record_recv", ret);
		tconn_connection_abort(tc, 1);
		return;
	}

	if (gnutls_record_check_pending(tc->sess) ||
	    tc->rx_start != tc->rx_end || tc->rx_eof)
		iv_task_register(&tc->rx_task);

	verify_state(tc);

	if (ret == GNUTLS_E_REHANDSHAKE) {
		fprintf(stderr, "received HelloRequest\n");
	} else {
		tc->record_received(tc->cookie, buf, ret);
	}
}

static void tconn_do_record_send(struct tconn *tc)
{
	int ret;

	ret = gnutls_record_send(tc->sess, NULL, 0);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && tconn_tx_flush(tc))
		ret = gnutls_record_send(tc->sess, NULL, 0);

	if (ret == GNUTLS_E_AGAIN) {
		verify_state(tc);
		return;
	}

	if (ret < 0) {
		gtls_perror("gnutls_record_send", ret);
		tconn_connection_abort(tc, 1);
		return;
	}

	// @@@ handle fewer bytes having been sent than passed in

	if (tc->state == STATE_TX_CONGESTION) {
		tc->state = STATE_RUNNING;
		verify_state(tc);
	} else {
		fprintf(stderr, "handle_record_send: called in state %d\n",
			tc->state);
		tconn_connection_abort(tc, 1);
	}
}

static void tconn_rx_task_handler(void *_tc)
{
	struct tconn *tc = _tc;

	if (tc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(tc->sess) == 0 &&
	    (tc->io_error || tc->rx_start != tc->rx_end || tc->rx_eof)) {
		tconn_do_handshake(tc, 1);
		return;
	}

	if ((tc->state == STATE_RUNNING || tc->state == STATE_TX_CONGESTION) &&
	    (gnutls_record_check_pending(tc->sess) || tc->io_error ||
	     tc->rx_start != tc->rx_end || tc->rx_eof)) {
		tconn_do_record_recv(tc);
		return;
	}

	abort();
}

static void tconn_tx_task_handler(void *_tc)
{
	struct tconn *tc = _tc;

	if (tc->state == STATE_HANDSHAKE &&
	    gnutls_record_get_direction(tc->sess) == 1 &&
	    (tc->io_error || tc->tx_bytes < sizeof(tc->tx_buf))) {
		tconn_do_handshake(tc, 1);
		return;
	}

	if (tc->state == STATE_TX_CONGESTION &&
	    (tc->io_error || tc->tx_bytes < sizeof(tc->tx_buf))) {
		tconn_do_record_send(tc);
		return;
	}

	abort();
}

static int tconn_verify_cert(gnutls_session_t sess)
{
	struct tconn *tc = gnutls_transport_get_ptr(sess);
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	gnutls_x509_crt_t peercert;
	int ret;
	gnutls_pubkey_t peerkey;
	uint8_t peerid[NODE_ID_LEN];

	/*
	 * TBD: @@@
	 * - verify that key is different from our key
	 * - verify key length
	 * - verify that certificate signature is correct
	 * - verify that signature corresponds to given public key
	 */

	cert_list = gnutls_certificate_get_peers(tc->sess, &cert_list_size);
	if (cert_list_size != 1) {
		fprintf(stderr, "tconn_verify_cert: unexpected cert count\n");
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

	ret = get_pubkey_id(peerid, peerkey);
	if (ret) {
		gtls_perror("get_pubkey_id", ret);
		goto err_free_key;
	}

	if (0) {
		fprintf(stderr, "%p: ", tc);
		print_fingerprint(stderr, peerid);
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

	return tc->verify_key_id(tc->cookie, peerid);

err_free_key:
	gnutls_pubkey_deinit(peerkey);

err_free_crt:
	gnutls_x509_crt_deinit(peercert);

err:
	return 1;
}

static int tconn_start_handshake(struct tconn *tc)
{
	int ret;
	gnutls_x509_crt_t cert;

	ret = gnutls_certificate_allocate_credentials(&tc->cert);
	if (ret) {
		gtls_perror("gnutls_certificate_allocate_credentials", ret);
		goto err;
	}

	gnutls_certificate_set_verify_function(tc->cert, tconn_verify_cert);

	ret = x509_generate_cert(&cert, tc->privkey);
	if (ret)
		goto err_free;

	ret = gnutls_certificate_set_x509_key(tc->cert, &cert, 1, tc->privkey);
	gnutls_x509_crt_deinit(cert);

	if (ret) {
		gtls_perror("gnutls_certificate_set_x509_key", ret);
		goto err_free;
	}

	ret = gnutls_credentials_set(tc->sess, GNUTLS_CRD_CERTIFICATE,
				     tc->cert);
	if (ret) {
		gtls_perror("gnutls_credentials_set", ret);
		goto err_free;
	}

	tc->state = STATE_HANDSHAKE;

	ret = tconn_do_handshake(tc, 0);
	if (ret)
		goto err_free;

	return 0;

err_free:
	gnutls_certificate_free_credentials(tc->cert);

err:
	return -1;
}

int tconn_start(struct tconn *tc)
{
	static char prio[] =
		"NONE:+CIPHER-ALL:+ECDHE-RSA:+MAC-ALL:+COMP-NULL:"
		"+VERS-TLS1.2:+SIGN-ALL:+CURVE-SECP256R1:%SAFE_RENEGOTIATION";
	unsigned int flags;
	int ret;
	const char *err;

	flags = GNUTLS_NONBLOCK | GNUTLS_NO_EXTENSIONS;
	if (tc->role == TCONN_ROLE_SERVER)
		flags |= GNUTLS_SERVER;
	else
		flags |= GNUTLS_CLIENT;

	ret = gnutls_init(&tc->sess, flags);
	if (ret) {
		gtls_perror("gnutls_init", ret);
		goto err;
	}

	if (tc->role == TCONN_ROLE_SERVER) {
		gnutls_certificate_server_set_request(tc->sess,
						      GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(tc->sess, 1);
	}

	ret = gnutls_priority_set_direct(tc->sess, prio, &err);
	if (ret) {
		const char *p;

		gtls_perror("gnutls_priority_set_direct", ret);

		fprintf(stderr, "%s\n", prio);
		for (p = prio; p < err; p++)
			fprintf(stderr, " ");
		fprintf(stderr, "^ error in priority string\n");

		goto err_deinit;
	}

	gnutls_transport_set_ptr(tc->sess, tc);
	gnutls_transport_set_pull_function(tc->sess, tconn_gtls_pull_func);
	gnutls_transport_set_push_function(tc->sess, tconn_gtls_push_func);

	tc->fd->cookie = tc;
	iv_fd_set_handler_in(tc->fd, tconn_fd_handler_in);
	iv_fd_set_handler_out(tc->fd, NULL);
	iv_fd_set_handler_err(tc->fd, NULL);

	tc->io_error = 0;

	IV_TASK_INIT(&tc->rx_task);
	tc->rx_task.cookie = tc;
	tc->rx_task.handler = tconn_rx_task_handler;
	tc->rx_start = 0;
	tc->rx_end = 0;
	tc->rx_eof = 0;

	IV_TASK_INIT(&tc->tx_task);
	tc->tx_task.cookie = tc;
	tc->tx_task.handler = tconn_tx_task_handler;
	tc->tx_bytes = 0;

	ret = tconn_start_handshake(tc);
	if (ret)
		goto err_deinit;

	return 0;

err_deinit:
	gnutls_deinit(tc->sess);

err:
	return -1;
}

void tconn_destroy(struct tconn *tc)
{
	verify_state(tc);

	iv_fd_set_handler_in(tc->fd, NULL);
	iv_fd_set_handler_out(tc->fd, NULL);

	gnutls_deinit(tc->sess);

	gnutls_certificate_free_credentials(tc->cert);

	if (iv_task_registered(&tc->rx_task))
		iv_task_unregister(&tc->rx_task);

	if (iv_task_registered(&tc->tx_task))
		iv_task_unregister(&tc->tx_task);
}

int tconn_record_send(struct tconn *tc, const uint8_t *rec, int len)
{
	int ret;

	verify_state(tc);

	if (tc->state == STATE_TX_CONGESTION) {
		return 0;
	} else if (tc->state != STATE_RUNNING) {
		fprintf(stderr, "got packet in [%d]\n", tc->state);
		return -1;
	}

	ret = gnutls_record_send(tc->sess, rec, len);
	if ((ret > 0 || ret == GNUTLS_E_AGAIN) && tconn_tx_flush(tc))
		ret = gnutls_record_send(tc->sess, NULL, 0);

	if (ret < 0 && ret != GNUTLS_E_AGAIN) {
		gtls_perror("gnutls_record_send", ret);
		tconn_connection_abort(tc, 0);
		return -1;
	}

	if (ret == GNUTLS_E_AGAIN)
		tc->state = STATE_TX_CONGESTION;

	// @@@ handle fewer bytes having been sent than passed in

	verify_state(tc);

	return 0;
}
