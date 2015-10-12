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
 * - cache socket i/o readiness status, possibly coalesce into own buffers
 * - coalesce on output, set a task to flush out
 * - byte/time limits, renegotiation
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
#include "pconn.h"
#include "x509.h"

#define STATE_HANDSHAKE		1
#define STATE_RUNNING		2
#define STATE_TX_CONGESTION	3
#define STATE_DEAD		4

static char prio[] =
	"NONE:+CIPHER-ALL:+ECDHE-RSA:+MAC-ALL:+COMP-NULL:+VERS-TLS1.2:"
	"+SIGN-ALL:+CURVE-SECP256R1:%SAFE_RENEGOTIATION";

static void gtls_perror(const char *str, int error)
{
	fprintf(stderr, "%s: %s\n", str, gnutls_strerror(error));
}

static ssize_t pconn_rx(gnutls_transport_ptr_t _pc, void *buf, size_t len)
{
	struct pconn *pc = _pc;
	int ret;

#if 1
	if (random() < 0.45 * RAND_MAX) {
		gnutls_transport_set_errno(pc->sess, EAGAIN);
		return -1;
	}

	if (random() < 0.82 * RAND_MAX) {
		gnutls_transport_set_errno(pc->sess, EINTR);
		return -1;
	}

	ret = recv(pc->ifd.fd, buf, 1, 0);
#else
	ret = recv(pc->ifd.fd, buf, len, 0);
#endif

	if (ret < 0)
		gnutls_transport_set_errno(pc->sess, errno);

	return ret;
}

static ssize_t pconn_tx(gnutls_transport_ptr_t _pc, const void *buf, size_t len)
{
	struct pconn *pc = _pc;
	int ret;

#if 1
	if (random() < 0.45 * RAND_MAX) {
		gnutls_transport_set_errno(pc->sess, EAGAIN);
		return -1;
	}

	if (random() < 0.82 * RAND_MAX) {
		gnutls_transport_set_errno(pc->sess, EINTR);
		return -1;
	}

	ret = send(pc->ifd.fd, buf, 1, 0);
#else
	ret = send(pc->ifd.fd, buf, len, 0);
#endif

	if (ret < 0)
		gnutls_transport_set_errno(pc->sess, errno);

	return ret;
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

static void connection_abort(struct pconn *pc)
{
	iv_fd_set_handler_in(&pc->ifd, NULL);
	iv_fd_set_handler_out(&pc->ifd, NULL);

	if (iv_timer_registered(&pc->handshake_timeout))
		iv_timer_unregister(&pc->handshake_timeout);

	pc->state = STATE_DEAD;

	pc->connection_lost(pc);
}

static void handle_record_recv(void *_pc)
{
	struct pconn *pc = _pc;
	uint8_t buf[16384];
	int ret;

again:
	do {
		ret = gnutls_record_recv(pc->sess, buf, sizeof(buf));
	} while (ret == GNUTLS_E_INTERRUPTED);

	if (ret == GNUTLS_E_AGAIN)
		return;

	if (ret == GNUTLS_E_REHANDSHAKE) {
		fprintf(stderr, "received HelloRequest\n");
		return;
	}

	if (ret <= 0) {
		if (ret)
			gtls_perror("gnutls_record_recv", ret);
		connection_abort(pc);
		return;
	}

	pc->record_received(pc->cookie, buf, ret);

	if (gnutls_record_check_pending(pc->sess))
		goto again;
}

static void handshake_timeout(void *_pc)
{
	struct pconn *pc = _pc;

	connection_abort(pc);
}

static void handle_handshake(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	do {
		ret = gnutls_handshake(pc->sess);
	} while (ret == GNUTLS_E_INTERRUPTED);

	if (ret == GNUTLS_E_AGAIN) {
		if (gnutls_record_get_direction(pc->sess) == 0) {
			iv_fd_set_handler_in(&pc->ifd, handle_handshake);
			iv_fd_set_handler_out(&pc->ifd, NULL);
		} else {
			iv_fd_set_handler_in(&pc->ifd, NULL);
			iv_fd_set_handler_out(&pc->ifd, handle_handshake);
		}
		return;
	}

	if (ret) {
		gtls_perror("gnutls_handshake", ret);
		connection_abort(pc);
		return;
	}

	gnutls_record_disable_padding(pc->sess);

	iv_fd_set_handler_in(&pc->ifd, handle_record_recv);
	iv_fd_set_handler_out(&pc->ifd, NULL);

	pc->state = STATE_RUNNING;

	iv_timer_unregister(&pc->handshake_timeout);

	pc->handshake_done(pc->cookie);
}

static void handle_record_send(void *_pc)
{
	struct pconn *pc = _pc;
	int ret;

	do {
		ret = gnutls_record_send(pc->sess, NULL, 0);
	} while (ret == GNUTLS_E_INTERRUPTED);

	if (ret == GNUTLS_E_AGAIN)
		return;

	if (ret < 0) {
		gtls_perror("gnutls_record_send", ret);
		connection_abort(pc);
		return;
	}

	// @@@ handle less bytes having been sent than passed in

	iv_fd_set_handler_out(&pc->ifd, NULL);

	if (pc->state == STATE_TX_CONGESTION) {
		pc->state = STATE_RUNNING;
	} else {
		fprintf(stderr, "handle_record_send: called in state %d\n",
			pc->state);
		connection_abort(pc);
	}
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
	if (ret < 0)
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

	handle_handshake((void *)pc);

	return 0;

err_free:
	gnutls_certificate_free_credentials(pc->cert);

err:
	return -1;
}

int pconn_start(struct pconn *pc)
{
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
	gnutls_transport_set_pull_function(pc->sess, pconn_rx);
	gnutls_transport_set_push_function(pc->sess, pconn_tx);

	IV_FD_INIT(&pc->ifd);
	pc->ifd.fd = pc->fd;
	pc->ifd.cookie = pc;
	iv_fd_register(&pc->ifd);

	IV_TIMER_INIT(&pc->handshake_timeout);
	pc->handshake_timeout.cookie = pc;
	pc->handshake_timeout.handler = handshake_timeout;

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

	do {
		ret = gnutls_record_send(pc->sess, record, len);
	} while (ret == GNUTLS_E_INTERRUPTED);

	if (ret == GNUTLS_E_AGAIN) {
		pc->state = STATE_TX_CONGESTION;
		iv_fd_set_handler_out(&pc->ifd, handle_record_send);
	} else if (ret < 0) {
		gtls_perror("gnutls_record_send", ret);
		connection_abort(pc);
	}

	// @@@ handle less bytes having been sent than passed in

	return 0;
}

void pconn_destroy(struct pconn *pc)
{
	gnutls_deinit(pc->sess);

	gnutls_certificate_free_credentials(pc->cert);

	iv_fd_unregister(&pc->ifd);

	if (iv_timer_registered(&pc->handshake_timeout))
		iv_timer_unregister(&pc->handshake_timeout);
}
