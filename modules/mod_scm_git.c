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

typedef struct tTokenizer {
	char **tokens;
	int numTokens;
} tTokenizer;

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

char* config_read(const char *filename, char *key)
{
	FILE *fp;
	char line[BUFSIZE];

	fp = fopen(filename, "r");
	if (fp == NULL)
		return NULL;

	while (!feof(fp)) {
		fgets(line, sizeof(line), fp);

		if (strncmp(line, key, strlen(key)) == 0) {
			char *tmp = strdup( line + strlen(key) + 3 );
			if (tmp[strlen(tmp) - 1] == '\n')
				tmp[strlen(tmp) - 1] = 0;

			return tmp;
		}
	}
	fclose(fp);

	return NULL;
}

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

int cmd_requires_authorization(char *cmd)
{
	return ((strcmp(cmd, "DELETE") == 0) || (strcmp(cmd, "CREATE") == 0)
		|| (strcmp(cmd, "DAEMON") == 0));
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	char *repo_dir;
	char *git_binary;
	char *git_user = NULL;
	char *git_group = NULL;

	if ((git_binary = config_read(config_file, "scm.git.binary")) == NULL) {
		DPRINTF("%s: Missing 'scm.git.binary' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if (access(git_binary, X_OK) != 0) {
		DPRINTF("%s: Cannot find git executable. Please set valid git binary to 'scm.git.binary' "
			"entry in %s\n", __FUNCTION__, config_file);

		return -EINVAL;
	}

	if ((repo_dir = config_read(config_file, "scm.git.repo_dir")) == NULL) {
		DPRINTF("%s: Missing 'scm.git.repo_dir' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	git_user = config_read(config_file, "scm.git.user");
	git_group = config_read(config_file, "scm.git.group");

	if ((git_user && (getuid() != 0))
		|| (git_group && (getgid() != 0))) {
		DPRINTF("%s: Cannot change user since application is not running as root. Please "
			"comment out scm.git.{user|group} entries from the config file or run as root.\n",
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
		char cmd[BUFSIZE];
		char path[BUFSIZE];
		char old_path[BUFSIZE];

		strncpy(name, t.tokens[3], sizeof(name));
		if (strstr(name, ".git") == NULL)
			strcat(name, ".git");

		snprintf(path, sizeof(path), "%s/%s", repo_dir, name);
		if (access(path, X_OK) == 0) {
			DPRINTF("%s: Repository %s already exists\n", __FUNCTION__, name);
			return -EEXIST;
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
			return -ENOENT;
		}

		if (strcmp(t.tokens[4], "SET") != 0)
			return -EINVAL;

		if (strcmp(t.tokens[5], "SERVER") == 0)
			snprintf(path, sizeof(path), "%s/%s/server", repo_dir, name);
		else
		if (strcmp(t.tokens[5], "DESCRIPTION") == 0)
			snprintf(path, sizeof(path), "%s/%s/description", repo_dir, name);

		fp = fopen(path, "w");
		if (fp == NULL)
			return -EIO;

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
			return -ENOENT;
		}

		snprintf(path, sizeof(path), "rm -rf %s/%s", repo_dir, name);
		DPRINTF("%s: About to run '%s'\n", __FUNCTION__, path);
		system(path);
	}
	else
	if (strcmp(t.tokens[1], "DAEMON") == 0) {
		int ret = -EINVAL;
		char cmd[BUFSIZE];

		if ((strcmp(t.tokens[2], "ENABLE") != 0)
			&& (strcmp(t.tokens[2], "DISABLE") != 0))
			return ret;

		snprintf(cmd, sizeof(cmd), "%s %s 2> /dev/null >/dev/null", MODULE_SERVICE,
			(strcmp(t.tokens[2], "ENABLE") == 0) ? "start" : "stop");

		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		ret = WEXITSTATUS( system(cmd) );

		return ret;
	}
	else
		return -ENOTSUP;

	return 0;
}

void free_tokens(tTokenizer t)
{
	int i;

	for (i = 0; i < t.numTokens; i++) {
		free(t.tokens[i]);
		t.tokens[i] = NULL;
	}
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

