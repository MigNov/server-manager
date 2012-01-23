#define	MODULE_CMD_SERVER	"/usr/bin/svnserve"
#define MODULE_FILE_SERVER	"/etc/xinetd.d/svn"
#define	MODULE_INIT_SCRIPT	"/etc/init.d/svn"
#define MODULE_IDENTIFICATION	"SCM SVN module"
#define MODULE_KEYWORD          "SCM-SVN"
#define MODULE_PORT		PORT_TCP(3690)
#define DEBUG_MOD_SVN

#include "../manager.h"
#include "mod_scm_svn.h"

#ifdef DEBUG_MOD_SVN
#define DPRINTF(fmt, args...) \
do { printf("mod_scm_svn: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

char *srvmgr_module_identification(void)
{
	return MODULE_IDENTIFICATION;
}

char *srvmgr_module_get_keyword(void)
{
	return MODULE_KEYWORD;
}

int srvmgr_module_get_port(void)
{
	return MODULE_PORT;
}

char *srvmgr_module_install(char *base_path)
{
	char *val = NULL;
        char config_file[BUFSIZE];

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		return strdup("ERR");
	}

	val = config_read(config_file, "scm.svn.user");
	return val ? strdup(val) : strdup("ERR");
}

int srvmgr_module_install_post(char *base_path)
{
	int ret = -EINVAL;
	FILE *fp = NULL;
	char cmd[BUFSIZE];
	char *user = NULL;
	char *binary = NULL;
	char *repo_dir = NULL;
        char config_file[BUFSIZE];

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		return ret;
	}

	if ((binary = config_read(config_file, "scm.svn.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.svn.binary' entry in %s\n", __FUNCTION__,
			config_file);

		return ret;
	}

	if (access(binary, X_OK) != 0) {
		DPRINTF("%s: Cannot find SVN executable. Please set valid SVN binary to 'scm.svn.binary' "
				"entry in %s\n", __FUNCTION__, config_file);

		return ret;
	}

	if ((repo_dir = config_read(config_file, "scm.svn.repo_dir")) == NULL) {
		DPRINTF("%s: Missing 'scm.svn.repo_dir' entry in %s\n", __FUNCTION__,
			config_file);

		return ret;
	}

	user = config_read(config_file, "scm.svn.user");
	if (user == NULL)
		return ret;

	if (access(repo_dir, X_OK) != 0) {
	        snprintf(cmd, sizeof(cmd), "%s -v -o %s -g %s -m 0755 -d %s 2>/dev/null > /dev/null",
			CMD_INSTALL, user, user, repo_dir);
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		ret = WEXITSTATUS(system(cmd));
		if (ret != 0)
			return ret;
	}

	if (access(MODULE_INIT_SCRIPT, R_OK) != 0) {
		fp = fopen(CONFIG_INETD, "a");
		if (fp == NULL)
			return -EACCES;

		fprintf(fp, "svn stream tcp nowait %s %s svnserve -i\n", user, MODULE_CMD_SERVER);
		fclose(fp);

		fp = fopen(MODULE_FILE_SERVER, "w");
		if (fp == NULL)
			return -EACCES;

		fprintf(fp, svn_inetd_script, user, MODULE_CMD_SERVER, repo_dir);
		fclose(fp);

		fp = fopen("/etc/sysconfig/svn", "w");
		if (fp == NULL)
			return -EACCES;

		fprintf(fp, "REPODIR=\"%s\"\n", repo_dir);
		fclose(fp);

		fp = fopen("/tmp/svn-wrapper", "w");
		fputs(svn_init_script_wrapper, fp);
		fclose(fp);
		chmod(MODULE_INIT_SCRIPT, 0755);
		system("/tmp/svn-wrapper");

		unlink("/tmp/svn-wrapper");

		fp = fopen(MODULE_INIT_SCRIPT, "w");
		if (fp == NULL)
			return -EACCES;

		fputs(svn_init_script, fp);
		fclose(fp);

		chmod(MODULE_INIT_SCRIPT, 0755);
		system("chkconfig svn on");
	}

        return 0;
}

int cmd_requires_authorization(char *cmd)
{
	return ((strcmp(cmd, "DELETE") == 0) || (strcmp(cmd, "CREATE") == 0));
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	char *repo_dir;
	char *svn_binary;
	char *svn_user = NULL;
	char *svn_group = NULL;

	if ((svn_binary = config_read(config_file, "scm.svn.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.svn.binary' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if (access(svn_binary, X_OK) != 0) {
		DPRINTF("%s: Cannot find SVN executable. Please set valid SVN binary to 'scm.svn.binary' "
			"entry in %s\n", __FUNCTION__, config_file);

		return -EINVAL;
	}

	if ((repo_dir = config_read(config_file, "scm.svn.repo_dir")) == NULL) {
		DPRINTF("%s: Missing 'scm.svn.repo_dir' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	svn_user = config_read(config_file, "scm.svn.user");
	svn_group = config_read(config_file, "scm.svn.group");

	if ((svn_user && (getuid() != 0))
		|| (svn_group && (getgid() != 0))) {
		DPRINTF("%s: Cannot change user since application is not running as root. Please "
			"comment out scm.svn.{user|group} entries from the config file or run as root.\n",
			__FUNCTION__);
		return -EINVAL;
	}

	if (t.numTokens == 0)
		return -EIO;

	if (cmd_requires_authorization(t.tokens[1]) && !authorized)
		return -EACCES;

	/* Repository creation command received */
	if ((strcmp(t.tokens[1], "CREATE") == 0)
		&& (strcmp(t.tokens[2], "REPO") == 0)) {
		int i;
		char name[64];
		char path[BUFSIZE];
		char old_path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) == 0) {
			DPRINTF("%s: Repository %s already exists\n", __FUNCTION__, name);
			return -EEXIST;
		}

		getcwd(old_path, sizeof(old_path));
		chdir(repo_dir);

		DPRINTF("%s: Path changed to '%s'\n", __FUNCTION__, repo_dir);

		snprintf(path, sizeof(path), "svnadmin create %s", name);
		system(path);

		if ((svn_user != NULL) && (svn_group != NULL)) {
			snprintf(path, sizeof(path), "chown -R %s.%s %s", svn_user, svn_group,
					name);
			DPRINTF("%s: Running '%s'\n", __FUNCTION__, path);
			system(path);
		}

		if (t.numTokens > 4) {
			if (strcmp(t.tokens[4], "ALLOW-ALL") == 0) {
				snprintf(path, sizeof(path), "%s/conf/svnserve.conf", name);
				FILE *fp = fopen(path, "w");
				fprintf(fp, "[general]\nanon-access = write\nauth-access = write\n");
				fclose(fp);

				DPRINTF("%s: Allowing full access for all users\n", __FUNCTION__);
			}
			else
			if (strcmp(t.tokens[4], "FOR") == 0) {
				char *svnuser, *svnpass;
				if (t.numTokens < 8)
					return -EINVAL;
				svnuser = strdup(t.tokens[5]);
				if (strcmp(t.tokens[6], "PASSWORD") == 0)
					svnpass = strdup(t.tokens[7]);

				users_add(svnuser, svnpass, svn_group, "SVN User", NULL, NULL);

				snprintf(path, sizeof(path), "chown -R %s.%s %s", svnuser, svn_group,
						name);
				DPRINTF("%s: Running '%s'\n", __FUNCTION__, path);
				system(path);
			}
		}

		chdir(old_path);
		DPRINTF("%s: Path restored to '%s'\n", __FUNCTION__, old_path);
	}
	else
        /* Repository deletion command received */
	if ((strcmp(t.tokens[1], "DELETE") == 0)
		&& (strcmp(t.tokens[2], "REPO") == 0)) {
		char name[64];
		char path[BUFSIZE];
		char old_path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) != 0) {
			DPRINTF("%s: Repository '%s' doesn't exist\n", __FUNCTION__, name);
			return -ENOENT;
		}

		snprintf(path, sizeof(path), "rm -rf %s/%s", repo_dir, name);
		DPRINTF("%s: About to run '%s'\n", __FUNCTION__, path);
		system(path);
	}
	else
		return -ENOTSUP;

	return 0;
}

int srvmgr_module_is_applicable(char *base_path)
{
        int ret = 1;
        char *binary;
        char config_file[BUFSIZE];

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		ret = 0;
	}

	if ((binary = config_read(config_file, "scm.svn.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.svn.binary' entry in %s\n", __FUNCTION__,
			config_file);

		ret = 0;
	}

	if (access(binary, X_OK) != 0) {
		DPRINTF("%s: Cannot find git executable. Please set valid git binary to 'scm.git.binary' "
			"entry in %s\n", __FUNCTION__, config_file);

		ret = 0;
	}

	free(binary);

	return ret;
}

int srvmgr_module_run(char *base_path, char *data, int authorized)
{
	char config_file[BUFSIZE];
	tTokenizer t;
	int ret;

	if (strncmp(data, MODULE_KEYWORD, strlen(MODULE_KEYWORD)) != 0)
		return -ENOTSUP;

	DPRINTF("[%s] Input data: '%s' ( user %s authorized )\n", MODULE_IDENTIFICATION,
		data, authorized ? "is" : "NOT");

	t = tokenize(data);
	if (t.numTokens == 0)
		return -EINVAL;

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		free_tokens(t);
		return -EINVAL;
	}

	ret = process_commands(config_file, authorized, t);
	free_tokens(t);

	return ret;
}

