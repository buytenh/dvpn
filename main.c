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
#include <string.h>

int dvpn_main(int argc, char *argv[]);
int hostmon_main(int argc, char *argv[]);
int rtmon_main(int argc, char *argv[]);
int topomon_main(int argc, char *argv[]);

static char *get_tool_name(char *argv0)
{
	char *tool;

	tool = argv0;
	if (tool == NULL)
		return NULL;

	while (*tool != 0) {
		char *delim;

		delim = strchr(tool, '/');
		if (delim == NULL)
			break;

		tool = delim + 1;
	}

	return tool;
}

int main(int argc, char *argv[])
{
	char *tool;

	tool = get_tool_name(argv[0]);
	if (tool != NULL) {
		if (!strcmp(tool, "hostmon") || !strcmp(tool, "dvpn-hostmon"))
			return hostmon_main(argc, argv);

		if (!strcmp(tool, "rtmon") || !strcmp(tool, "dvpn-rtmon"))
			return rtmon_main(argc, argv);

		if (!strcmp(tool, "topomon") || !strcmp(tool, "dvpn-topomon"))
			return topomon_main(argc, argv);
	}

	return dvpn_main(argc, argv);
}
