#define DEBUG_SOCKETS

#include "manager.h"

#ifdef DEBUG_SOCKETS
#define DPRINTF(fmt, args...) \
do { printf("sockets: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

int socket_check_auth(char *token)
{
	int i;

	if (strncmp(token, "AUTH TOKEN", 10) != 0)
		return 0;

	for (i = 0; i < 11; i++)
		*token++;

	return (strcmp(token, ADMINPWD) == 0);
}

int process_with_module(char *base_path, char *data, int authorized)
{
	return module_process_all(base_path, data, authorized);
}

int socket_bind(char *base_path, char *path)
{
	struct sockaddr_un addr;
	int sock;
	fd_set rfds, wfds;

	DPRINTF("%s: Base path is set to '%s'\n", __FUNCTION__, base_path);
	DPRINTF("%s: Binding to '%s'\n", __FUNCTION__, path);
	unlink(path);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		return -errno;

	if (listen(sock, 1) != 0)
		return -errno;

	signal(SIGPIPE, SIG_IGN);

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);

	/* Enable access to other users on the system, e.g. apache user */
	chmod(path, 0666);

	while (1) {
		if (select(sock+1, &rfds, NULL, NULL, NULL) > 0) {
			if (FD_ISSET(sock, &rfds)) {
				int fd;

				fd = accept(sock, NULL, NULL);
				if (fd < 0)
					continue;
				if (fork() == 0) {
					char *cmd;
					int authorized = 0;
					char buf[4096] = { 0 };
					int ret = 0;

					close(sock);
					if (write(fd, BANNER, strlen(BANNER)) <= 0)
						return 1;
					if (read(fd, buf, sizeof(buf)) <= 0)
						return 2;
					if ((strstr(buf, "AUTH") != NULL) && (strchr(buf, '\n') != NULL)) {
						cmd = strchr(buf, '\n') + 1;

						if (cmd[strlen(cmd) - 1] == '\n')
							cmd[strlen(cmd) - 1] = 0;

						buf[ strlen(buf) - strlen(cmd) - 1] = 0;
						authorized = socket_check_auth(buf);
					}
					else
						cmd = strdup(buf);

					ret = process_with_module(base_path, cmd, authorized);
					DPRINTF("Command returned %d (%s)\n", ret, strerror(-ret));

					if (ret != 0)
						snprintf(buf, sizeof(buf), "ERR%d", -ret);
					else
						snprintf(buf, sizeof(buf), "OK");

					write(fd, buf, strlen(buf));

					close(fd);
					exit((ret == 0) ? 1 : 0);
				}
			}
		}
	}

	wait(NULL);

	close(sock);
	unlink(SOCKET_PATH);
	return 0;
}

int socket_write(char *path, char *admtoken, char *data)
{
	struct sockaddr_un addr;
	int sock, flags;
	fd_set rfds;
	char buf[1024], *packet;
	int size;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if ((flags = fcntl(sock, F_GETFD)) < 0) {
		close(sock);
		return -1;
	}
	flags |= FD_CLOEXEC;
	if (fcntl(sock, F_SETFD, flags) < 0) {
		close(sock);
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		return -errno;

	memset(buf, 0, sizeof(buf));
	if (read(sock, buf, sizeof(buf)) > 0)
		printf("Server returned '%s'\n", buf);

	if (admtoken != NULL) {
		size = (strlen(data) + 256 );
		packet = (char *)malloc( size * sizeof(char) );
		memset(packet, 0, size);
		snprintf(packet, size, "AUTH TOKEN %s\n%s\n", admtoken, data);
		write(sock, packet, size);
		fsync(sock);
	}
	else
		write(sock, data, strlen(data));

	memset(buf, 0, sizeof(buf));
	if (read(sock, buf, sizeof(buf)) > 0)
		printf("Server returned '%s'\n", buf);

	close(sock);

	return 0;
}

