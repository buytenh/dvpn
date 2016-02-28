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
#include <getopt.h>
#include <string.h>

int dvpn(const char *config);
int gencert(const char *keyfile);
int hostmon(const char *config);
int rtmon(const char *config);
int show_key_id(const char *file);
int topomon(const char *config);

enum {
	TOOL_UNKNOWN = 0,
	TOOL_DVPN,
	TOOL_GENCERT,
	TOOL_HOSTMON,
	TOOL_RTMON,
	TOOL_SHOW_KEY_ID,
	TOOL_TOPOMON,
};

static int tool = TOOL_UNKNOWN;

static void set_tool(int newtool)
{
	if (tool != TOOL_UNKNOWN) {
		fprintf(stderr, "error: can only select one tool to run\n");
		exit(1);
	}

	tool = newtool;
}

static void try_determine_tool(char *argv0)
{
	char *t;

	if (argv0 == NULL)
		return;

	t = argv0;
	while (*t != 0) {
		char *delim;

		delim = strchr(t, '/');
		if (delim == NULL)
			break;

		t = delim + 1;
	}

	if (!strcmp(t, "dvpn")) {
		tool = TOOL_DVPN;
		return;
	}

	if (!strcmp(t, "gencert") || !strcmp(t, "dvpn-gencert")) {
		tool = TOOL_GENCERT;
		return;
	}

	if (!strcmp(t, "hostmon") || !strcmp(t, "dvpn-hostmon")) {
		tool = TOOL_HOSTMON;
		return;
	}

	if (!strcmp(t, "rtmon") || !strcmp(t, "dvpn-rtmon")) {
		tool = TOOL_RTMON;
		return;
	}

	if (!strcmp(t, "show-key-id") || !strcmp(t, "dvpn-show-key-id")) {
		tool = TOOL_SHOW_KEY_ID;
		return;
	}

	if (!strcmp(t, "topomon") || !strcmp(t, "dvpn-topomon")) {
		tool = TOOL_TOPOMON;
		return;
	}
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "config-file", required_argument, 0, 'c' },
		{ "gencert", no_argument, 0, 'g' },
		{ "hostmon", no_argument, 0, 'h' },
		{ "rtmon", no_argument, 0, 'r' },
		{ "show-key-id", no_argument, 0, 's' },
		{ "topomon", no_argument, 0, 't' },
		{ 0, 0, 0, 0, },
	};
	const char *config = "/etc/dvpn.ini";

	while (1) {
		int c;

		c = getopt_long(argc, argv, "c:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config = optarg;
			break;

		case 'g':
			set_tool(TOOL_GENCERT);
			break;

		case 'h':
			set_tool(TOOL_HOSTMON);
			break;

		case 'r':
			set_tool(TOOL_RTMON);
			break;

		case 's':
			set_tool(TOOL_SHOW_KEY_ID);
			break;

		case 't':
			set_tool(TOOL_TOPOMON);
			break;

		case '?':
			fprintf(stderr, "syntax: %s [-c <config.ini>]\n",
				argv[0]);
			return 1;

		default:
			abort();
		}
	}

	if (tool == TOOL_UNKNOWN)
		try_determine_tool(argv[0]);

	switch (tool) {
	case TOOL_DVPN:
		return dvpn(config);
	case TOOL_GENCERT:
		return gencert(argv[optind]);
	case TOOL_HOSTMON:
		return hostmon(config);
	case TOOL_RTMON:
		return rtmon(config);
	case TOOL_SHOW_KEY_ID:
		return show_key_id(argv[optind]);
	case TOOL_TOPOMON:
		return topomon(config);
	}

	return dvpn(config);
}
