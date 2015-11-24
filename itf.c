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
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include "itf.h"

static int spawnvp(const char *file, char * const *argv)
{
	pid_t pid;
	int status;
	int ret;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		execvp(file, argv);
		perror("execvp");
		exit(-1);
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		perror("waitpid");
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;

	return 0;
}

int itf_add_v6(const char *itf, const uint8_t *addr, int len)
{
	char *args[7];
	char caddr[64];
	int ret;

	args[0] = "ip";
	args[1] = "addr";
	args[2] = "add";
	args[3] = caddr;
	args[4] = "dev";
	args[5] = strdup(itf);
	args[6] = NULL;

	inet_ntop(AF_INET6, addr, caddr, sizeof(caddr));
	sprintf(caddr + strlen(caddr), "/%d", len);

	ret = spawnvp("ip", args);

	free(args[5]);

	return ret;
}

int itf_set_state(const char *itf, int up)
{
	char *args[6];
	int ret;

	args[0] = "ip";
	args[1] = "link";
	args[2] = "set";
	args[3] = strdup(itf);
	args[4] = up ? "up" : "down";
	args[5] = NULL;

	ret = spawnvp("ip", args);

	free(args[3]);

	return ret;
}
