/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>

static const char prog_name[] = "soc_term";

static struct termios old_term;

static void usage(void)
{
	fprintf(stderr, "Usage: %s [-t,-e] <port>\n", prog_name);
	fprintf(stderr, "\t-t: no input\n");
	fprintf(stderr, "\t-e: automatically login and run Event Manager (only for Normal World!)\n");
	exit(1);
}

static int get_port(const char *str)
{
	long port;
	char *eptr;

	if (*str == '\0')
		usage();

	port = strtol(str, &eptr, 10);
	if (port < 1 || *eptr != '\0')
		usage();
	return (int)port;
}

static int get_listen_fd(const char *port_str)
{
	struct sockaddr_in sain;
	int fd;
	int on;
	int port = get_port(port_str);

	memset(&sain, 0, sizeof(sain));
	sain.sin_family = AF_INET;
	sain.sin_port = htons(port);
	sain.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(sain.sin_family, SOCK_STREAM, 0);
	if (fd == -1)
		err(1, "socket");

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		err(1, "setsockopt");

	if (bind(fd, (struct sockaddr *)&sain, sizeof(sain)))
		err(1, "bind");

	if (listen(fd, 5))
		err(1, "listen");

	return fd;

}

static int accept_fd(int listen_fd)
{
	struct sockaddr_storage sastor;
	socklen_t slen = sizeof(sastor);
	int fd = accept(listen_fd, (struct sockaddr *)&sastor, &slen);

	if (fd == -1)
		err(1, "accept");
	return fd;
}

static void save_current_termios(void)
{
	if (tcgetattr(STDIN_FILENO, &old_term) == -1)
		err(1, "save_current_termios: tcgetattr");
}

static void restore_termios(void)
{
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term) == -1)
		err(1, "restore_termios: tcsetattr");
}

static void set_tty_noncanonical(void)
{
	int fd = STDIN_FILENO;
	struct termios t;

	t = old_term;

	t.c_lflag &= ~(ICANON | ECHO | ISIG);

	t.c_iflag &= ~ICRNL;

	t.c_cc[VMIN] = 1;                   /* Character-at-a-time input */
	t.c_cc[VTIME] = 0;                  /* with blocking */

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == -1)
		err(1, "set_tty_noncanonical: tcsetattr");
}

static bool write_buf(int fd, const void *buf, size_t count)
{
	const uint8_t *b = buf;
	size_t num_written = 0;

	while (num_written < count) {
		ssize_t res = write(fd, b + num_written, count - num_written);

		if (res == -1)
			return false;

		num_written += res;
	}
	return true;
}

#define END_SEQ_LEN 4
uint8_t end_sequence[END_SEQ_LEN] = {'q', 'q', 'q', 'q'};
size_t seq_n = 0;

#define INPUT_SEQ_LEN 6
uint8_t input_sequence[INPUT_SEQ_LEN] = {'l', 'o', 'g', 'i', 'n', ':'};
size_t input_seq_n = 0;

#define SHELL_SEQ_LEN 1
uint8_t shell_sequence[INPUT_SEQ_LEN] = {'#'};
size_t shell_seq_n = 0;

#define LOGIN_INPUT_LEN 5
uint8_t login_input_buf[LOGIN_INPUT_LEN] = {'r', 'o', 'o', 't', '\n'};

#define EM_INPUT_LEN 20
uint8_t em_input_buf[EM_INPUT_LEN] = {'o', 'p', 't', 'e', 'e', '_',
																			'e', 'x', 'a', 'm', 'p', 'l', 'e', '_',
																			'e', 'v', 'e', 'n', 't', '\n'};

bool check_sequence(uint8_t *buf, size_t n, size_t *seq_ptr, uint8_t *sequence, uint8_t seq_length) {
	int i;

	for(i=0; i<n; i++) {
		if(buf[i] == sequence[*seq_ptr]) {
			*seq_ptr += 1;
		}
		else {
			*seq_ptr = 0;
			continue;
		}

		if(*seq_ptr == seq_length) {
			//warnx("\nSequence found! %d\n", seq_length);
			return true;
		}
	}

	return false;
}

static void write_input(int fd, uint8_t *buf, size_t buf_len) {
	if (!write_buf(fd, buf, buf_len)) {
		errx(1, "auto_input failed");
	}
}

static void serve_fd(int fd, bool auto_input)
{
	uint8_t buf[512];
	struct pollfd pfds[2];
	bool logged_in = false, stop_auto_input = false;

	memset(pfds, 0, sizeof(pfds));
	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;
	pfds[1].fd = fd;
	pfds[1].events = POLLIN;

	seq_n = 0;

	while (true) {
		size_t n;

		if (poll(pfds, 2, -1) == -1)
			err(1, "poll");

		if (pfds[0].revents & POLLIN) {
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n == -1)
				err(1, "read stdin");
			if (!auto_input && n == 0)
				errx(1, "read stdin EOF");

			if(check_sequence(buf, n, &seq_n, end_sequence, END_SEQ_LEN)) {
				warnx("\nManual stop triggered.\n");
				exit(0);
			}

			/* TODO handle case when this write blocks */
			if (!write_buf(fd, buf, n)) {
				warn("write_buf fd");
				break;
			}
		}

		if (pfds[1].revents & POLLIN) {
			n = read(fd, buf, sizeof(buf));
			if (n == -1) {
				warn("read fd");
				break;
			}
			if (n == 0) {
				warnx("read fd EOF");
				break;
			}

			if(auto_input && !stop_auto_input && check_sequence(buf, n, &input_seq_n, input_sequence, INPUT_SEQ_LEN)) {
				write_input(fd, login_input_buf, LOGIN_INPUT_LEN);
				logged_in = true;
			}

			if(auto_input && !stop_auto_input && logged_in && check_sequence(buf, n, &shell_seq_n, shell_sequence, SHELL_SEQ_LEN)) {
				write_input(fd, em_input_buf, EM_INPUT_LEN);
				stop_auto_input = true; // finished
			}

			if(!auto_input || (auto_input && stop_auto_input)) {
				if (!write_buf(STDOUT_FILENO, buf, n))
					err(1, "write_buf stdout");
				}
			}
	}
}

void sig_handler(int signum){
	exit(1);
}


int main(int argc, char *argv[])
{
	int listen_fd;
	char *port;
	bool have_input = true, auto_input = false;

	signal(SIGINT, sig_handler);

	switch (argc) {
	case 2:
		port = argv[1];
		break;
	case 3:
		if (strcmp(argv[1], "-t") == 0) {
			have_input = false;
		}
		else if(strcmp(argv[1], "-e") == 0) {
			have_input = false;
			auto_input = true;
		}
		else {
			usage();
		}

		port = argv[2];
		break;
	default:
		usage();
	}


	listen_fd = get_listen_fd(port);

	printf("listening on port %s\n", port);
	if (have_input)
		save_current_termios();

	while (true) {
		int fd = accept_fd(listen_fd);

		warnx("accepted fd %d", fd);

		if (have_input)
			set_tty_noncanonical();

		serve_fd(fd, auto_input);
		if (close(fd))
			err(1, "close");
		fd = -1;

		if (have_input)
			restore_termios();
	}
}
