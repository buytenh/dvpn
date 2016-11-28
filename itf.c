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
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include "itf.h"

#define DEBUG	0

static void print_args(char *const *argv)
{
	const char *sep = "";
	char *const *ptr;

	ptr = argv;
	while (*ptr != NULL) {
		fprintf(stderr, "%s%s", sep, *ptr);
		sep = " ";
		ptr++;
	}
}

static int spawnvp(const char *file, char *const *argv)
{
	pid_t pid;
	int status;

	if (DEBUG) {
		fprintf(stderr, "running \"%s\", \"", file);
		print_args(argv);
		fprintf(stderr, "\"\n");
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		int err;

		execvp(file, argv);

		err = errno;
		fprintf(stderr, "execvp(\"%s\", \"", file);
		print_args(argv);
		fprintf(stderr, "\"): %s\n", strerror(err));

		exit(1);
	}

	do {
		int ret;

		do {
			ret = waitpid(pid, &status, 0);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			perror("waitpid");
			return -1;
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	if (WIFSIGNALED(status)) {
		if (DEBUG) {
			fprintf(stderr, "child died with signal %d%s\n",
				WTERMSIG(status),
				WCOREDUMP(status) ? " and dumped core" : "");
		}
		return -1;
	}

	if (WEXITSTATUS(status)) {
		if (DEBUG) {
			fprintf(stderr, "child terminated with exit code %d\n",
				WEXITSTATUS(status));
		}
		return -1;
	}

	return 0;
}

int itf_add_addr_v6(const char *itf, const uint8_t *addr, int len)
{
	char caddr[64];
	char *args[7];

	inet_ntop(AF_INET6, addr, caddr, sizeof(caddr));
	sprintf(caddr + strlen(caddr), "/%d", len);

	args[0] = "ip";
	args[1] = "addr";
	args[2] = "add";
	args[3] = caddr;
	args[4] = "dev";
	args[5] = (char *)itf;
	args[6] = NULL;

	return spawnvp("ip", args);
}

static int
__route_v6_direct(char *action, const uint8_t *dest, const char *itf)
{
	char daddr[64];
	char *args[7];

	inet_ntop(AF_INET6, dest, daddr, sizeof(daddr));

	args[0] = "ip";
	args[1] = "route";
	args[2] = action;
	args[3] = daddr;
	args[4] = "dev";
	args[5] = (char *)itf;
	args[6] = NULL;

	return spawnvp("ip", args);
}

int itf_add_route_v6_direct(const uint8_t *addr, const char *itf)
{
	return __route_v6_direct("add", addr, itf);
}

int itf_chg_route_v6_direct(const uint8_t *addr, const char *itf)
{
	return __route_v6_direct("chg", addr, itf);
}

int itf_del_route_v6_direct(const uint8_t *addr, const char *itf)
{
	return __route_v6_direct("del", addr, itf);
}

int itf_set_mtu(const char *itf, int mtu)
{
	char cmtu[32];
	char *args[7];

	sprintf(cmtu, "%d", mtu);

	args[0] = "ip";
	args[1] = "link";
	args[2] = "set";
	args[3] = (char *)itf;
	args[4] = "mtu";
	args[5] = cmtu;
	args[6] = NULL;

	return spawnvp("ip", args);
}

int itf_set_state(const char *itf, int up)
{
	char *args[6];

	args[0] = "ip";
	args[1] = "link";
	args[2] = "set";
	args[3] = (char *)itf;
	args[4] = up ? "up" : "down";
	args[5] = NULL;

	if (spawnvp("ip", args))
		return -1;

	if (up) {
		char path[256];
		int fd;

		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", itf);

		fd = open(path, O_WRONLY);
		if (fd >= 0) {
			write(fd, "0\n", 2);
			close(fd);
		}
	}

	return 0;
}
