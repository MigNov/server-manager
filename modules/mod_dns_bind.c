#define MODULE_IDENTIFICATION	"DNS BIND Module"
#define MODULE_KEYWORD		"DNS-BIND"
#define MODULE_PORT		PORT_BOTH(53)
#define MODULE_SERVICE		"service named"
#define MODULE_MASTER_ZONETABLE	"named.rfc1912.zones"
#define DEBUG_MOD_DNS

#include "../manager.h"

#ifdef DEBUG_MOD_DNS
#define DPRINTF(fmt, args...) \
do { printf("mod_dns_bind: " fmt , ##args); } while (0)
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

char *srvmgr_module_install(void)
{
	int ret;
	char cmd[64];

	snprintf(cmd, sizeof(cmd), "%s status 2> /dev/null > /dev/null", MODULE_SERVICE);
	ret = WEXITSTATUS(system(cmd));
	DPRINTF("%s: Command '%s' returned %d\n", __FUNCTION__, cmd, ret);
	if (ret == 1)
		return strdup( "ERR" );

	return strdup( "named" );
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

gid_t users_group_id(char *name)
{
	struct group *gr;

	gr = getgrnam(name);
	if (gr == NULL)
		return -1;

	return gr->gr_gid;
}

uid_t users_user_id(char *name)
{
        struct passwd *pw;

	pw = getpwnam(name);
	if (pw == NULL)
		return -1;

	return pw->pw_uid;
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	char *ns1 = NULL;
	char *user = NULL;
	char *group = NULL;
	char *chroot_dir = NULL;

	if ((user = config_read(config_file, "dns.bind.user")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.user' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if ((group = config_read(config_file, "dns.bind.group")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.group' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if ((ns1 = config_read(config_file, "dns.bind.nameserver")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.nameserver' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if ((chroot_dir = config_read(config_file, "dns.bind.chroot")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.chroot' entry in %s\n", __FUNCTION__,
			config_file);

		return -EINVAL;
	}

	if (t.numTokens == 0)
		return -EIO;

	if (cmd_requires_authorization(t.tokens[1]) && !authorized)
		return -EACCES;

	if (strcmp(t.tokens[1], "CREATE") == 0) {
		if (t.numTokens < 4)
			return -EINVAL;

		if (strcmp(t.tokens[2], "ZONE") == 0) {
			char path[BUFSIZE];
			char line[BUFSIZE];
			char b[BUFSIZE];
			int exists = 0;

			snprintf(path, sizeof(path), "%s/etc/%s", chroot_dir, MODULE_MASTER_ZONETABLE);

			FILE *fp = fopen(path, "r");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open '%s' for reading\n", __FUNCTION__, path);
				return -EIO;
			}
			
			snprintf(b, sizeof(b), "zone \"%s\" IN {\n", t.tokens[3]);
			while (!feof(fp)) {
				memset(line, 0, sizeof(line));
				
				fgets(line, sizeof(line), fp);
				
				if (strcmp(line, b) == 0)
					exists = 1;
			}
			
			fclose(fp);
			
			if (exists) {
				DPRINTF("%s: Zone %s already exists\n", __FUNCTION__, t.tokens[3]);
				return -EEXIST;
			}

			fp = fopen(path, "a");
			if (fp == NULL) {
				DPRINTF("%s: Cannot access '%s'\n", __FUNCTION__, path);
				return -EIO;
			}

			fprintf(fp, "zone \"%s\" IN {\n\ttype master;\n\tfile \"%s.db\";\n\tallow-update { any; };\n};\n",
				t.tokens[3], t.tokens[3]);
			fclose(fp);

			if (chown(path, users_user_id(user), users_group_id(group)) != 0) {
				DPRINTF("%s: Cannot alter permissions on '%s' (%d, %d)\n", __FUNCTION__, path,
						users_user_id(user), users_group_id(group));
				return -EPERM;
			}

			snprintf(path, sizeof(path), "%s/var/named/%s.db", chroot_dir, t.tokens[3]);

			fp = fopen(path, "w");
			if (fp == NULL) {
				DPRINTF("%s: Cannot access '%s'\n", __FUNCTION__, path);
				return -EIO;
			}
			fprintf(fp, "$TTL 86400\n$ORIGIN %s.\n@ IN SOA %s. %s. %d%d 10800 3600 604800 3600\n"
					"@ IN NS      %s.\n", t.tokens[3], ns1, ns1, time(NULL), rand() % 100, ns1);
			fclose(fp);

			if (chown(path, users_user_id(user), users_group_id(group)) != 0) {
				DPRINTF("%s: Cannot alter permissions on '%s' (%d, %d)\n", __FUNCTION__, path,
						users_user_id(user), users_group_id(group));
				return -EPERM;
			}
		}
		else
		if (strcmp(t.tokens[3], "RECORD") == 0) {
			int i;
			char *domain = NULL;
			char *type = strdup( t.tokens[2] );
			char path[BUFSIZE];
			char line[1024] = { 0 };
			char data[256] = { 0 };
			char name[256] = { 0 };
			char name2[256] = { 0 };
			int exists = 0;
			FILE *fp = NULL;

			if ((strcmp(type, "A") != 0) && (strcmp(type, "NS") != 0)
				&& (strcmp(type, "CNAME") != 0) && (strcmp(type, "AAAA") != 0)
				&& (strcmp(type, "TXT") != 0) && (strcmp(type, "SRV") != 0)) {
				DPRINTF("%s: Invalid DNS record type (%s)\n", __FUNCTION__, type);
				free(type);
				return -EINVAL;
			}

			for (i = 4; i < t.numTokens-1; i++) {
				if (strcmp(t.tokens[i], "FOR") == 0)
					domain = strdup(t.tokens[i+1]);
				else {
					strcat(data, t.tokens[i]);
					strcat(data, " ");
				}
			}

			if ((strlen(data) > 1) && (data[ strlen(data) - 1] == ' '))
				data[ strlen(data) - 1] = 0;

			if (domain == NULL) {
				DPRINTF("%s: Domain is not specified\n", __FUNCTION__);
				free(type);
				return -EINVAL;
			}

			strncpy(name, domain, sizeof(name));
			for (i = 0; i < strlen(name); i++)
				if (name[i] == '.')
					break;

			name[i] = 0;

			domain += strlen(name) + 1;

			snprintf(path, sizeof(path), "%s/var/named/%s.db", chroot_dir, domain);
			if (access(path, R_OK) != 0) {
				DPRINTF("%s: Cannot access domain zone file '%s'\n", __FUNCTION__, path);
				free(type);
				return -EINVAL;
			}

			fp = fopen(path, "r");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open domain zone file '%s' for reading\n", __FUNCTION__, path);
				free(type);
				return -EINVAL;
			}

			strcpy(name2, name);
			strcat(name2, " ");
			while (!feof(fp)) {
				memset(line, 0, sizeof(line));

				fgets(line, sizeof(line), fp);
				if (strncmp(line, name2, strlen(name2)) == 0)
					exists = 1;
			}
			fclose(fp);

			if (exists) {
				DPRINTF("%s: Cannot create entry. Entry already exists\n", __FUNCTION__);
				free(type);
				return -EEXIST;
			}

			fp = fopen(path, "a");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open domain zone file '%s' for writing\n", __FUNCTION__, path);
				free(type);
				return -EINVAL;
			}
			fprintf(fp, "%s IN %s %s\n", name, type, data);
			fclose(fp);

			DPRINTF("%s: %s record %s.%s created and saved into %s\n", __FUNCTION__, type, name, domain, path);
			free(type);
		}
		else
			return -ENOTSUP;
	}
	else
	if (strcmp(t.tokens[1], "DELETE") == 0) {
		if (t.numTokens < 4)
			return -EINVAL;

		if (strcmp(t.tokens[2], "ZONE") == 0) {
			char path[BUFSIZE];
			char line[BUFSIZE];
			char tmp[BUFSIZE];
			char b[BUFSIZE];
			int skip = 0;
			int deleted = 0;

			snprintf(path, sizeof(path), "%s/etc/%s", chroot_dir, MODULE_MASTER_ZONETABLE);
			FILE *fp = fopen(path, "r");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open '%s' for reading\n", __FUNCTION__, path);
				return -EIO;
			}
			
			strcpy(tmp, "/tmp/srvmgr-bind.XXXXXX");
			mkstemp(tmp);
			
			FILE *fp2 = fopen(tmp, "w");
			if (fp2 == NULL) {
				DPRINTF("%s: Cannot open '%s' for writing\n", __FUNCTION__, tmp);
				return -EIO;
			}

			snprintf(b, sizeof(b), "zone \"%s\" IN {\n", t.tokens[3]);
			while (!feof(fp)) {
				memset(line, 0, sizeof(line));
				
				fgets(line, sizeof(line), fp);
				
				if (strcmp(line, b) == 0)
					skip = 1;
					
				if (!skip)
					fputs(line, fp2);
				else
					deleted = 1;

				if ((skip > -1) && (strncmp(line, "};", 2) == 0))
					skip = 0;
			}
			
			fclose(fp2);
			
			if (!deleted) {
				DPRINTF("%s: Zone %s not found\n", __FUNCTION__, t.tokens[3]);
				return -ENOENT;
			}

			snprintf(b, sizeof(b), "mv %s %s", tmp, path);
			system(b);
			
			DPRINTF("%s: Running '%s'\n", __FUNCTION__, b);
			
			if (chown(path, users_user_id(user), users_group_id(group)) != 0) {
				DPRINTF("%s: Cannot alter permissions on '%s' (%d, %d)\n", __FUNCTION__, path,
						users_user_id(user), users_group_id(group));
				return -EPERM;
			}

			snprintf(path, sizeof(path), "%s/var/named/%s.db", chroot_dir, t.tokens[3]);
			unlink(path);
		}
		else
		if (strcmp(t.tokens[2], "RECORD") == 0) {
			int i;
			char *domain = strdup( t.tokens[3] );
			char path[BUFSIZE];
			char line[1024] = { 0 };
			char tmp[256] = { 0 };
			char name[256] = { 0 };
			char name2[256] = { 0 };
			int deleted = 0;
			FILE *fp = NULL;
			FILE *fp2 = NULL;

			if (domain == NULL) {
				DPRINTF("%s: Domain is not specified\n", __FUNCTION__);
				return -EINVAL;
			}

			strncpy(name, domain, sizeof(name));
			for (i = 0; i < strlen(name); i++)
				if (name[i] == '.')
					break;

			name[i] = 0;

			domain += strlen(name) + 1;

			strcpy(tmp, "/tmp/srvmgr-bind.XXXXXX");
			mkstemp(tmp);

			snprintf(path, sizeof(path), "%s/var/named/%s.db", chroot_dir, domain);
			if (access(path, R_OK) != 0) {
				DPRINTF("%s: Cannot access domain zone file '%s'\n", __FUNCTION__, path);
				return -EINVAL;
			}

			fp = fopen(path, "r");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open domain zone file '%s' for reading\n", __FUNCTION__, path);
				return -EINVAL;
			}

			fp2 = fopen(tmp, "w");
			if (fp == NULL) {
				DPRINTF("%s: Cannot open domain zone file '%s' for writing\n", __FUNCTION__, path);
				return -EINVAL;
			}

			strcpy(name2, name);
			strcat(name2, " ");
			while (!feof(fp)) {
				memset(line, 0, sizeof(line));

				fgets(line, sizeof(line), fp);
				if (strncmp(line, name2, strlen(name2)) != 0)
					fputs(line, fp2);
				else
					deleted = 1;
			}
			fclose(fp2);
			fclose(fp);
			
			if (!deleted) {
				DPRINTF("%s: Entry %s.%s doesn't exist\n", __FUNCTION__, name, domain);
				unlink(tmp);
				return -ENOENT;
			}

			DPRINTF("%s: %s.%s deleted from %s\n", __FUNCTION__, name, domain, path);

			snprintf(line, sizeof(tmp), "mv %s %s", tmp, path);
			system(line);
			
			DPRINTF("%s: Running '%s'\n", __FUNCTION__, line);
			
			if (chown(path, users_user_id(user), users_group_id(group)) != 0) {
				DPRINTF("%s: Cannot alter permissions on '%s' (%d, %d)\n", __FUNCTION__, path,
						users_user_id(user), users_group_id(group));
				return -EPERM;
			}
		}
		else
			return -ENOTSUP;
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
	char cmd[64];
	char *tmp = NULL;
	char config_file[BUFSIZE];

        snprintf(cmd, sizeof(cmd), "%s status 2> /dev/null >/dev/null", MODULE_SERVICE);
	if (WEXITSTATUS(system(cmd)) == 1) {
		DPRINTF("%s: Cannot access required service\n", __FUNCTION__);
		ret = 0;
	}

	snprintf(config_file, sizeof(config_file), "%s/manager.conf", base_path);
	if (access(config_file, R_OK) != 0) {
		DPRINTF("%s: Cannot read configuration file '%s'\n", __FUNCTION__,
			config_file);
		ret = 0;
	}

	if ((tmp = config_read(config_file, "dns.bind.user")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.user' entry in %s\n", __FUNCTION__,
			config_file);

		ret = 0;
        }
	free(tmp);

	if ((tmp = config_read(config_file, "dns.bind.group")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.group' entry in %s\n", __FUNCTION__,
			config_file);

		ret = 0;
	}
	free(tmp);

	if ((tmp = config_read(config_file, "dns.bind.nameserver")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.nameserver' entry in %s\n", __FUNCTION__,
			config_file);

		ret = 0;
	}
	free(tmp);

	if ((tmp = config_read(config_file, "dns.bind.chroot")) == NULL) {
		DPRINTF("%s: Missing 'dns.bind.chroot' entry in %s\n", __FUNCTION__,
			config_file);

		ret = 0;
	}
	free(tmp);

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

