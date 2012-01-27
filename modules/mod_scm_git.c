#define MODULE_IDENTIFICATION	"SCM Git module"
#define MODULE_KEYWORD		"SCM-GIT"
#define MODULE_PORT		PORT_TCP(9418)
#define MODULE_INIT_SCRIPT	"/etc/init.d/git-daemon"
#define MODULE_SYSCONFIG	"/etc/sysconfig/git-daemon"
#define MODULE_SERVICE		"service git-daemon"
#define DEBUG_MOD_GIT

#include "../manager.h"
#include "mod_scm_git.h"

#ifdef DEBUG_MOD_GIT
#define DPRINTF(fmt, args...) \
do { printf("mod_scm_git: " fmt , ##args); } while (0)
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

int create_scripts(void)
{
	FILE *fp;

	if (access(MODULE_INIT_SCRIPT, X_OK) != 0) {
		fp = fopen(MODULE_INIT_SCRIPT, "w");
		if (fp == NULL)
			return -EACCES;

		fputs(git_init_script, fp);
		fclose(fp);

		chmod(MODULE_INIT_SCRIPT, 0755);
	}

	if (access(MODULE_SYSCONFIG, R_OK) != 0) {
		fp = fopen(MODULE_SYSCONFIG, "w");
		if (fp == NULL)
			return -EACCES;

		fputs(git_sysconfig, fp);
		fclose(fp);
	}

	return 0;
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

	val = config_read(config_file, "scm.git.user");
	if (val == NULL)
		return strdup( "ERR" );

	if (create_scripts() != 0)
		return strdup( "ERR" );

	return strdup( val );
}

char *srvmgr_module_install_post(char *base_path)
{
	char cmd[BUFSIZE];
	char *val = NULL;
	char *keyfile = NULL;
	char config_file[BUFSIZE];

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		return strdup("ERR");
	}

	val = config_read(config_file, "scm.git.user");
	if (val == NULL)
		return strdup( "ERR" );

	keyfile = config_read(config_file, "scm.git.public_key");
	if (keyfile == NULL) {
		DPRINTF("%s: Keyfile is not defined. Please define it first\n", __FUNCTION__);
		return strdup( "ERR" );
	}

	if (access(keyfile, R_OK) != 0) {
		DPRINTF("%s: Cannot access public key file '%s'\n", __FUNCTION__, keyfile);
		return strdup( "ERR" );
	}

	snprintf(cmd, sizeof(cmd), "sudo -H -u %s gitosis-init < %s", val, keyfile);
	if (WEXITSTATUS(system(cmd)) != 0)
		return strdup( "ERR" );

	return strdup( val );
}

int cmd_requires_authorization(char *cmd)
{
	return ((strcmp(cmd, "DELETE") == 0) || (strcmp(cmd, "CREATE") == 0)
		|| (strcmp(cmd, "DAEMON") == 0));
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	int ret = -EINVAL;
	char *repo_dir;
	char *git_binary;
	char *git_user = NULL;
	char *git_group = NULL;
	char old_path[BUFSIZE] = { 0 };

	if ((git_binary = config_read(config_file, "scm.git.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.git.binary' entry in %s\n", __FUNCTION__,
			config_file);

		goto cleanup;
	}

	if (access(git_binary, X_OK) != 0) {
		DPRINTF("%s: Cannot find git executable. Please set valid git binary to 'scm.git.binary' "
			"entry in %s\n", __FUNCTION__, config_file);

		goto cleanup;
	}

	if ((repo_dir = config_read(config_file, "scm.git.repo_dir")) == NULL) {
		DPRINTF("%s: Missing 'scm.git.repo_dir' entry in %s\n", __FUNCTION__,
			config_file);

		goto cleanup;
	}

	git_user = config_read(config_file, "scm.git.user");
	git_group = config_read(config_file, "scm.git.group");

	if ((git_user && (getuid() != 0))
		|| (git_group && (getgid() != 0))) {
		DPRINTF("%s: Cannot change user since application is not running as root. Please "
			"comment out scm.git.{user|group} entries from the config file or run as root.\n",
			__FUNCTION__);
		goto cleanup;
	}

	if (t.numTokens == 0) {
		ret = -EIO;
		goto cleanup;
	}

	if (cmd_requires_authorization(t.tokens[1]) && !authorized) {
		ret = -EACCES;
		goto cleanup;
	}

	/* Repository creation command received */
	if ((strcmp(t.tokens[1], "CREATE") == 0)
		&& (strcmp(t.tokens[2], "REPO") == 0)) {
		int i;
		char name[64];
		char cmd[BUFSIZE];
		char path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		if (strstr(name, ".git") == NULL)
			strcat(name, ".git");

		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) == 0) {
			DPRINTF("%s: Repository %s already exists\n", __FUNCTION__, name);
			ret = -EEXIST;
			goto cleanup;
		}

		getcwd(old_path, sizeof(old_path));
		mkdir(path, 0755);
		chdir(path);

		DPRINTF("%s: Path changed to '%s'\n", __FUNCTION__, path);

		snprintf(cmd, sizeof(cmd), "%s --bare init --shared > /dev/null 2> /dev/null", git_binary);
		system(cmd);
		snprintf(cmd, sizeof(cmd),"%s config --file config http.receivepack true");
		system(cmd);

		if ((git_user != NULL) && (git_group != NULL)) {
			snprintf(path, sizeof(path), "chown -R %s.%s %s/%s", git_user, git_group,
					repo_dir, name);
			DPRINTF("%s: Running '%s'\n", __FUNCTION__, path);
			system(path);
		}

		for (i = 3; i < t.numTokens-1; i++) {
			if ((strcmp(t.tokens[i], "WITH") == 0)
				&& (strcmp(t.tokens[i+1], "DESCRIPTION") == 0)
				&& (t.numTokens > i + 1)) {
				FILE *fp;

				fp = fopen("description", "w");
				fprintf(fp, "%s\n", t.tokens[i+2]);
				fclose(fp);
			}
			else
			if ((strcmp(t.tokens[i], "FOR") == 0)
				&& (t.numTokens > i + 1)) {
				FILE *fp;

				fp = fopen("server", "w");
				fprintf(fp, "%s\n", t.tokens[i+1]);
				fclose(fp);
			}
		}

		chdir(old_path);
		DPRINTF("%s: Path restored to '%s'\n", __FUNCTION__, old_path);
	}
	else
	/* Repository alteration command */
	if ((strcmp(t.tokens[1], "ALTER") == 0)
		&& (strcmp(t.tokens[2], "REPO") == 0)) {
		FILE *fp;
		char name[64];
		char path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		if (strstr(name, ".git") == NULL)
			strcat(name, ".git");

		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) != 0) {
			DPRINTF("%s: Repository '%s' doesn't exist\n", __FUNCTION__, name);
			ret = -ENOENT;
			goto cleanup;
		}

		if (strcmp(t.tokens[4], "SET") != 0) {
			ret = -EINVAL;
			goto cleanup;
		}

		if (strcmp(t.tokens[5], "SERVER") == 0)
			snprintf(path, sizeof(path), "%s/%s/server", repo_dir, name);
		else
		if (strcmp(t.tokens[5], "DESCRIPTION") == 0)
			snprintf(path, sizeof(path), "%s/%s/description", repo_dir, name);

		fp = fopen(path, "w");
		if (fp == NULL) {
			ret = -EIO;
			goto cleanup;
		}

		if (t.tokens[6] != NULL) {
			fprintf(fp, "%s\n", t.tokens[6]);
			fclose(fp);

			DPRINTF("%s: Repository changed. %s is now %s\n", __FUNCTION__, t.tokens[5], t.tokens[6]);
		}
		else {
			fputs("", fp);
			fclose(fp);

			DPRINTF("%s: Repository changed. %s is empty string\n", __FUNCTION__, t.tokens[5]);
		}
	}
	else
        /* Repository deletion command received */
	if ((strcmp(t.tokens[1], "DELETE") == 0)
		&& (strcmp(t.tokens[2], "REPO") == 0)) {
		char name[64];
		char path[BUFSIZE];
		char old_path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		if (strstr(name, ".git") == NULL)
			strcat(name, ".git");

		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) != 0) {
			DPRINTF("%s: Repository '%s' doesn't exist\n", __FUNCTION__, name);
			ret = -ENOENT;
			goto cleanup;
		}

		snprintf(path, sizeof(path), "rm -rf %s/%s", repo_dir, name);
		DPRINTF("%s: About to run '%s'\n", __FUNCTION__, path);
		system(path);
	}
	else
	if (strcmp(t.tokens[1], "DAEMON") == 0) {
		char cmd[BUFSIZE];

		if ((strcmp(t.tokens[2], "ENABLE") != 0)
			&& (strcmp(t.tokens[2], "DISABLE") != 0))
			goto cleanup;

		snprintf(cmd, sizeof(cmd), "%s %s 2> /dev/null >/dev/null", MODULE_SERVICE,
			(strcmp(t.tokens[2], "ENABLE") == 0) ? "start" : "stop");

		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		ret = WEXITSTATUS( system(cmd) );
	}
	else
	if (strcmp(t.tokens[1], "SYNC-REPO") == 0) {
		char *out = NULL;
		char *user = NULL;
		char *host = NULL;
		char cmd[8192] = { 0 };

		if (t.numTokens < 2)
			goto cleanup;

		setenv("REPONAME", t.tokens[2], 1);
		out = process_handlers( config_read(config_file, "scm.git.ssh.get_repodir_cmd") );
		if (out == NULL)
			goto cleanup;

		if (strncmp(out, "ERROR", 5) == 0) {
			free(out);
			ret = -ENOENT;
			goto cleanup;
		}

		snprintf(cmd, sizeof(cmd), "%s/%s", repo_dir, t.tokens[2]);
		if (access(cmd, X_OK) != 0) {
			free(out);
			ret = -ENOENT;
			goto cleanup;
		}

		user = config_read(config_file, "scm.git.ssh.user");
		host = config_read(config_file, "scm.git.ssh.host");

		if ((user == NULL) || (host == NULL))
			snprintf(cmd, sizeof(cmd), "cp -af %s/%s %s", repo_dir, t.tokens[2], out);
		else
			snprintf(cmd, sizeof(cmd), "scp -r %s/%s %s@%s:%s", repo_dir, t.tokens[2], user, host, out);

		DPRINTF("%s: Command formatted to '%s'\n", __FUNCTION__, cmd);

		free(out);
		free(user);
		free(host);

		ret = 0;
	}
	else
	if (strcmp(t.tokens[1], "SYNC") == 0) {
		char *out = NULL;
		char *user = NULL;
		char *host = NULL;
		FILE *fp = NULL;
		char cmd[8192] = { 0 };

		if (t.numTokens < 2)
			goto cleanup;

		setenv("REPONAME", t.tokens[2], 1);
		out = process_handlers( config_read(config_file, "scm.git.ssh.get_repodir_cmd") );
		if (out == NULL) {
			DPRINTF("%s: Handler 'scm.git.ssh.get_repodir_cmd' not defined or not executable\n", __FUNCTION__);
			goto cleanup;
		}

		if (strncmp(out, "ERROR", 5) == 0) {
			free(out);
			ret = -ENOENT;
			goto cleanup;
		}

		snprintf(cmd, sizeof(cmd), "%s/%s", repo_dir, t.tokens[2]);
		if (access(cmd, X_OK) != 0) {
			DPRINTF("%s: Cannot find '%s'\n", __FUNCTION__, cmd);
			free(out);
			ret = -ENOENT;
			goto cleanup;
		}

		chdir(cmd);

		user = config_read(config_file, "scm.git.ssh.user");
		host = config_read(config_file, "scm.git.ssh.host");

		if ((user == NULL) || (host == NULL)) {
			free(user);
			free(host);
			free(out);

			ret = -EIO;
			goto cleanup;
		}

		snprintf(cmd, sizeof(cmd), "ssh %s@%s cat %s/.last-commit", user, host, out);
		DPRINTF("%s: Command to get last commit hash is '%s'\n", __FUNCTION__, cmd);

		fp = popen(cmd, "r");
		if (fp != NULL) {
			memset(cmd, 0, sizeof(cmd));
			fgets(cmd, sizeof(cmd), fp);
			fclose(fp);

			if ((strlen(cmd) > 0) && (cmd[strlen(cmd) - 1] == '\n'))
				cmd[strlen(cmd) - 1] = 0;

			if (strlen(cmd) > 0) {
				int num = 0;
				char *tmp = strdup(cmd);
				DPRINTF("%s: Last commit id is %s\n", __FUNCTION__, tmp);

				snprintf(cmd, sizeof(cmd), "let num=($(%s rev-list master | wc -l)-$(%s rev-list %s | wc -l)); echo $num",
						git_binary, git_binary, tmp);
				free(tmp);

				fp = popen(cmd, "r");
				fgets(cmd, sizeof(cmd), fp);
				fclose(fp);

				if ((strlen(cmd) > 0) && (cmd[strlen(cmd) - 1] == '\n'))
					cmd[strlen(cmd) - 1] = 0;

				num = atoi(cmd);

				if (num > 0) {
					DPRINTF("%s: Found %d new commits, formatting patch...\n", __FUNCTION__, num);
					snprintf(cmd, sizeof(cmd), "%s format-patch -%d --stdout > .patch-file", git_binary, num);
					DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
					system(cmd);
				}
				else {
					DPRINTF("%s: Invalid number of patches, seems to be up-to-date\n", __FUNCTION__);
					ret = -EEXIST;
				}
			}
			else {
				DPRINTF("%s: No last commit found, syncing all...\n", __FUNCTION__);

				snprintf(cmd, sizeof(cmd), "%s format-patch --all --stdout > .patch-file", git_binary);
				DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
				system(cmd);
			}

			if (ret == 0) {
				snprintf(cmd, sizeof(cmd), "scp .patch-file %s@%s:%s 1>& 2> /dev/null", user, host, out);
				DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
				system(cmd);
				snprintf(cmd, sizeof(cmd), "ssh %s@%s \"cd %s && cat .patch-file | patch --quiet -p1\"", user, host, out);
				DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
				ret = WEXITSTATUS(system(cmd));

				DPRINTF("%s: Patch apply error code is %d\n", __FUNCTION__, ret);
				if (ret != 0)
					ret = -EIO;

				unlink("./patch-file");
			}

			if (ret == 0) {
				char *tmp = NULL;

				snprintf(cmd, sizeof(cmd), "%s rev-list master | head -n 1", git_binary);
				fp = popen(cmd, "r");
				memset(cmd, 0, sizeof(cmd));
				fgets(cmd, sizeof(cmd), fp);
				fclose(fp);

				if ((strlen(cmd) > 0) && (cmd[strlen(cmd) - 1] == '\n'))
					cmd[strlen(cmd) - 1] = 0;

				tmp = strdup(cmd);
				DPRINTF("%s: Got latest commit ID of '%s'\n", __FUNCTION__, tmp);
				snprintf(cmd, sizeof(cmd), "ssh %s@%s \"echo %s > %s/.last-commit\"", user, host, tmp, out);
				DPRINTF("%s: Writing latest commit ID using '%s'\n", __FUNCTION__, cmd);
				system(cmd);
				free(tmp);
			}
		}
		free(out);
	}
	else
		ret = -ENOTSUP;

cleanup:
	if (strlen(old_path) > 0)
		chdir(old_path);

	free(git_binary);
	free(repo_dir);
	free(git_user);
	free(git_group);
	return ret;
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

	if ((binary = config_read(config_file, "scm.git.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.git.binary' entry in %s\n", __FUNCTION__,
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

