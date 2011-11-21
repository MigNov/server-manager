#define DEBUG_SOCKETS

#include "manager.h"

#ifdef DEBUG_SOCKETS
#define DPRINTF(fmt, args...) \
do { printf("sockets: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

tTokenizer tokenize(char *string)
{
	char *tmp;
	char *str;
	char *save;
	char *token;
	int i = 0;
	tTokenizer t;

	tmp = strdup(string);
	t.tokens = malloc( sizeof(char *) );
	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, " ", &save);
		if (token == NULL)
			break;

		t.tokens = realloc( t.tokens, (i + 1) * sizeof(char *) );
		t.tokens[i++] = strdup(token);
	}

	t.numTokens = i;

	return t;
}

void free_tokens(tTokenizer t)
{
	int i;

	for (i = 0; i < t.numTokens; i++) {
		free(t.tokens[i]);
		t.tokens[i] = NULL;
	}
}

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
	/* Hack for builtin commands */
	if (strcmp(data, "TEST") == 0)
		return 0;

	if (strncmp(data, "BUILTIN", 7) == 0) {
		int ret = 0;
		tTokenizer t;

		t = tokenize(data);
		if (t.numTokens < 3) {
			free_tokens(t);
			return -EINVAL;
		}

		if (strcmp(t.tokens[1], "USER") == 0) {
			if ((t.tokens[2], "ADD") == 0) {
				char *name, *password, *groupName, *description, *home, *shell;

				name = (t.numTokens > 3) ? t.tokens[3] : NULL;
				password = (t.numTokens > 4) ? t.tokens[4] : NULL;
				groupName = (t.numTokens > 5) ? t.tokens[5] : NULL;
				description = (t.numTokens > 6) ? t.tokens[6] : NULL;
				home = (t.numTokens > 7) ? t.tokens[7] : NULL;
				shell = (t.numTokens > 8) ? t.tokens[8] : NULL;

				ret = users_add(name, password, groupName, description, home, shell);
			}
			else
				ret = -ENOTSUP;
		}
		else
		if (strcmp(t.tokens[1], "GROUP") == 0) {
			if (strcmp(t.tokens[2], "ADD") == 0) {
				ret = users_group_add( (t.numTokens > 3) ? t.tokens[3] : NULL );
			}
			else
				ret = -ENOTSUP;
		}
		else
		if (strcmp(t.tokens[1], "FIREWALL") == 0) {
			if (strcmp(t.tokens[2], "INSERT") == 0) {
				int port, proto, type = IPT_TYPE_REJECT;

				port = atoi(t.tokens[3]);
				if (strcmp(t.tokens[4], "TCP") == 0)
					proto = IPT_PROTO_TCP;
				else
				if (strcmp(t.tokens[4], "UDP") == 0)
					proto = IPT_PROTO_UDP;
				else
				if (strcmp(t.tokens[4], "BOTH") == 0)
					proto = IPT_PROTO_TCP | IPT_PROTO_UDP;

				if (strcmp(t.tokens[5], "ACCEPT") == 0)
					type = IPT_TYPE_ACCEPT;

				ret = firewall_rule_insert( port, proto, type );
			}
			else
			if (strcmp(t.tokens[2], "DELETE") == 0) {
				int port, proto, type = IPT_TYPE_REJECT;

				port = atoi(t.tokens[3]);
				if (strcmp(t.tokens[4], "TCP") == 0)
					proto = IPT_PROTO_TCP;
				else
				if (strcmp(t.tokens[4], "UDP") == 0)
					proto = IPT_PROTO_UDP;
				else
				if (strcmp(t.tokens[4], "BOTH") == 0)
					proto = IPT_PROTO_TCP | IPT_PROTO_UDP;

				if (strcmp(t.tokens[5], "ACCEPT") == 0)
					type = IPT_TYPE_ACCEPT;

				ret = firewall_rule_delete( port, proto, type );
			}
		}
		free_tokens(t);

		return ret;
	}
	else
		return module_process_all(base_path, data, authorized);
}

int socket_bind(char *base_path, char *path)
{
	struct sockaddr_un addr;
	int sock;
	fd_set rfds, wfds;
	char *tmp_base_path = strdup(base_path);
	char *tmp_path = strdup(path);

	DPRINTF("%s: Base path is set to '%s'\n", __FUNCTION__, tmp_base_path);
	DPRINTF("%s: Binding to '%s'\n", __FUNCTION__, tmp_path);
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

