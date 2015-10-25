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
 * - tun interface carrier state control
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <iv.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include "tun.h"

static void tun_got_packet(void *cookie)
{
	struct tun_interface *ti = cookie;
	uint8_t buf[16384];
	int ret;

	do {
		ret = read(ti->fd.fd, buf, sizeof(buf));
	} while (ret == -1 && errno == EINTR);

	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EAGAIN)
				return;

			fprintf(stderr, "tun_got_packet: read(2) got "
					"error: %s\n", strerror(errno));
			exit(1);
		}
		return;
	}

	ti->got_packet(ti->cookie, buf, ret);
}

int tun_interface_register(struct tun_interface *ti)
{
	int fd;
	struct ifreq ifr;
	int ret;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "tun_interface_register: open(2) of "
				"/dev/net/tun got error: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (ti->itfname != NULL)
		strncpy(ifr.ifr_name, ti->itfname, IFNAMSIZ);

	ret = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if (ret < 0) {
		fprintf(stderr, "tun_interface_register: ioctl(2) got "
				"error: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	memcpy(ti->name, ifr.ifr_name, IFNAMSIZ);

	IV_FD_INIT(&ti->fd);
	ti->fd.fd = fd;
	ti->fd.cookie = ti;
	ti->fd.handler_in = tun_got_packet;
	iv_fd_register(&ti->fd);

	return 0;
}

void tun_interface_unregister(struct tun_interface *ti)
{
	iv_fd_unregister(&ti->fd);
	close(ti->fd.fd);
}

char *tun_interface_get_name(struct tun_interface *ti)
{
	return ti->name;
}

int tun_interface_send_packet(struct tun_interface *ti,
			      const uint8_t *buf, int len)
{
	int ret;

	do {
		ret = write(ti->fd.fd, buf, len);
	} while (ret < 0 && errno == EINTR);

	return ret;
}
