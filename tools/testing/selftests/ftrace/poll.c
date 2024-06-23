// SPDX-License-Identifier: GPL-2.0
/*
 * Simple poll on a file.
 *
 * Copyright (c) 2024 Google LLC.
 */

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#define BUFSIZE 4096

int main(int argc, char *argv[])
{
	struct pollfd pfd = {.events = POLLIN};
	char buf[BUFSIZE];

	if (argc < 2)
		return -1;
	pfd.fd = open(argv[1], O_RDONLY);
	if (pfd.fd < 0) {
		perror("open");
		return -1;
	}
	/* Read out once for cleanup polling status. */
	do {} while (read(pfd.fd, buf, BUFSIZE) > 0);

	if (poll(&pfd, 1, -1) < 0) {
		perror("poll");
		return -1;
	}
	close(pfd.fd);
	return 0;
}
