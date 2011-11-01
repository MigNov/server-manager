#define	BINARY_USERADD		"/usr/sbin/useradd"
#define BINARY_USERDEL		"/usr/sbin/userdel"
#define BINARY_GROUPADD		"/usr/sbin/groupadd"
#define BINARY_GROUPDEL		"/usr/sbin/groupdel"
#define SHELL_DEFAULT		"/sbin/nologin"
#define DEBUG_USERS

#include "manager.h"

#ifdef DEBUG_USERS
#define DPRINTF(fmt, args...) \
do { printf("users: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

int users_check_user(char *name)
{
	struct passwd *pw;

	pw = getpwnam(name);
	if (pw == NULL)
		return -ENOENT;

	DPRINTF("User %s details:\n", name);
	DPRINTF("\tUsername: %s\n",pw->pw_name);
	DPRINTF("\tPassword: %s\n", pw->pw_passwd);
	DPRINTF("\tReal name: %s\n", pw->pw_gecos);
	DPRINTF("\tUID/GID: %d/%d\n", pw->pw_uid, pw->pw_gid);
	DPRINTF("\tHome directory: %s\n", pw->pw_dir);
	DPRINTF("\tShell: %s\n", pw->pw_shell);

	return 0;
}

int users_check_group(char *name)
{
	struct group *gr;

	gr = getgrnam(name);
	if (gr == NULL)
		return -ENOENT;

	DPRINTF("Group %s details:\n", name);
	DPRINTF("\tGroup name: %s\n", gr->gr_name);
	DPRINTF("\tGroup password: %s\n", gr->gr_passwd);
	DPRINTF("\tGID: %d\n", gr->gr_gid);

	return 0;
}

int users_group_add(char *name)
{
	char cmd[BUFSIZE];

	if (users_check_group(name) == 0)
		return -EEXIST;

	snprintf(cmd, sizeof(cmd), "%s %s 2> /dev/null > /dev/null", BINARY_GROUPADD, name);
	DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
	return WEXITSTATUS(system(cmd));
}

int users_add(char *name, char *groupName, char *description, char *homeDir, char *shell)
{
	int ret;
	char cmd[BUFSIZE];
	char homedir[BUFSIZE];

	if (name == NULL)
		return -EINVAL;

	if (users_check_user(name) == 0) {
		DPRINTF("%s: User %s already exists\n", __FUNCTION__, name);
		return -EEXIST;
	}

	ret = users_group_add(groupName);

	if ((ret != 0) && (ret != -EEXIST)) {
		DPRINTF("%s: Group creation failed\n", __FUNCTION__);
		return -EIO;
	}

	if (homeDir == NULL)
		snprintf(homedir, sizeof(homedir), "/home/%s", name);
	else
		strncpy(homedir, homeDir, sizeof(homedir));

	snprintf(cmd, sizeof(cmd), "%s -c \"%s\" -d %s -m -g %s -s %s %s 2> /dev/null > /dev/null", BINARY_USERADD,
		description ? description : "-", homedir, groupName, shell ? shell : SHELL_DEFAULT, name);
	ret = WEXITSTATUS(system(cmd));
	DPRINTF("%s: Result of '%s' is %d\n", __FUNCTION__, cmd, ret);
	return ret;
}


