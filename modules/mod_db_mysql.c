#define MODULE_IDENTIFICATION	"Database MYSQL module"
#define MODULE_KEYWORD          "MYSQL"
#define MODULE_PORT		0

#define DEBUG_MOD_DB_MYSQL

#include "../manager.h"
#include <mysql/mysql.h>

#ifdef DEBUG_MOD_DB_MYSQL
#define DPRINTF(fmt, args...) \
do { printf("mod_db_mysql: " fmt , ##args); } while (0)
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

int srvmgr_module_is_applicable(char *base_path)
{
	int status;

	status = WEXITSTATUS(system("service mysqld status 2> /dev/null > /dev/null"));
	return (status <= 3);
}

char *srvmgr_module_install(void)
{
	if (!srvmgr_module_is_applicable(NULL))
		return strdup("ERR");

	return strdup( "mysql" );
}

int service_enable(int enable)
{
	int ret;
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "service mysqld %s > /dev/null &2> /dev/null", enable ? "start" : "stop");
	ret = WEXITSTATUS( system(cmd) );

	DPRINTF("%s: Command '%s' returned with error code %d\n", __FUNCTION__, cmd, ret);
	return ret;
}

int cmd_requires_authorization(char *cmd)
{
	return (strcmp(cmd, "TEST") != 0);
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	char *user = NULL;
	char *pass = NULL;
	char *host = NULL;
	char *port = NULL;
	char *sock = NULL;
	int portInt= 0;
	int    ret = 0;
	MYSQL  sql;

	if (t.numTokens < 2) {
		ret = -EIO;
		goto cleanup;
	}

	if (cmd_requires_authorization(t.tokens[1]) && !authorized) {
		ret = -EACCES;
		goto cleanup;
	}

	host = config_read(config_file, "db.mysql.host");
	user = config_read(config_file, "db.mysql.user");
	pass = config_read(config_file, "db.mysql.password");

	if (!host || !user || !pass) {
		ret = -EINVAL;
		goto cleanup;
	}

	DPRINTF("%s: Will try connection to %s@%s\n", __FUNCTION__, user, host);

	/* Those 2 values are optional */
	port = config_read(config_file, "db.mysql.port");
	if (port != NULL)
		portInt = atoi(port);

	sock = config_read(config_file, "db.mysql.sock");

	/* Now we need to decode from base64 as mysql_real_connect cannot accept it */
	pass = base64_decode(pass);
	if (pass == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	if (pass[strlen(pass) - 1] == '\n')
		pass[ strlen(pass) - 1] = 0;

	if (mysql_init(&sql) < 0) {
		ret = -EIO;
		goto cleanup;
	}

	if (mysql_real_connect(&sql, host, user, pass, NULL, portInt, sock, 0) == NULL) {
		DPRINTF("%s: mysql_real_connect failed (host %s, user %s, portInt %d, sock %s) with message '%s'\n",
			__FUNCTION__, host, user, portInt, sock ? sock : "<null>",
			mysql_error(&sql));
		ret = -EPERM;
		goto cleanup;
	}

	DPRINTF("%s: Connection to %s has been established successfully\n", __FUNCTION__, host);

	if (strcmp(t.tokens[1], "TEST") == 0) {
		ret = 0;
	}
	else
	if (strcmp(t.tokens[1], "CREATE") == 0) {
		if (t.numTokens < 3) {
			ret = -EINVAL;
			goto cleanup;
		}

		if (strcmp(t.tokens[2], "USER") == 0) {
			char qry[4096] = { 0 };
			char *pwd = NULL;

			if (t.numTokens < 8) {
				ret = -EINVAL;
				goto cleanup;
			}

			pwd = base64_decode(t.tokens[5]);
			if (pwd != NULL) {
				if (pwd[ strlen(pwd) - 1] == '\n')
					pwd[strlen(pwd) - 1] = 0;

				if (mysql_select_db(&sql, "mysql") != 0)
					DPRINTF("%s: Error occured on database switching: %s\n", __FUNCTION__,
						mysql_error(&sql));

				snprintf(qry, sizeof(qry), "CREATE USER '%s'@'%s' IDENTIFIED BY '%s'",
					t.tokens[3], (strcmp(t.tokens[7], "*") == 0) ? "%" : t.tokens[7], pwd);

				if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
					DPRINTF("%s: Error occured on user creation: %s\n", __FUNCTION__,
						mysql_error(&sql));
					ret = -EIO;
					goto cleanup;
				}

				DPRINTF("%s: User %s created successfully\n", __FUNCTION__, t.tokens[3]);

				snprintf(qry, sizeof(qry), "FLUSH PRIVILEGES");
				if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
					DPRINTF("%s: Error occured on flushing privileges: %s\n", __FUNCTION__,
						mysql_error(&sql));
					ret = -EIO;
					goto cleanup;
				}
			}
			else
				ret = -EIO;
		}
		else
		// CREATE DATABASE srvmgrtest_db1 FOR srvmgrtest ON localhost
		if (strcmp(t.tokens[2], "DATABASE") == 0) {
			char qry[4096] = { 0 };

			if (t.numTokens < 7) {
				ret = -EINVAL;
				goto cleanup;
			}

			snprintf(qry, sizeof(qry), "CREATE DATABASE %s", t.tokens[3]);
			DPRINTF("%s: Query formatted to '%s'\n", __FUNCTION__, qry);

			if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
				DPRINTF("%s: Error occured on user creation: %s\n", __FUNCTION__,
					mysql_error(&sql));
				ret = -EIO;
				goto cleanup;
			}

			DPRINTF("%s: Database %s created successfully\n", __FUNCTION__, t.tokens[3]);

			snprintf(qry, sizeof(qry), "GRANT ALL ON %s.* TO '%s'@'%s'", t.tokens[3],
				t.tokens[5], (strcmp(t.tokens[7], "*") == 0) ? "%" : t.tokens[7]);

			DPRINTF("%s: Query formatted to '%s'\n", __FUNCTION__, qry);

			if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
				DPRINTF("%s: Error occured on granting privileges: %s\n", __FUNCTION__,
					mysql_error(&sql));
				ret = -EIO;
				goto cleanup;
			}

			DPRINTF("%s: All privileges for database '%s' has been granted to user %s on host %s\n", __FUNCTION__,
				t.tokens[3], t.tokens[5], t.tokens[7]);
		}
		else
			ret = -ENOTSUP;
	}
	else
	if (strcmp(t.tokens[1], "DELETE") == 0) {
		if (t.numTokens < 3) {
			ret = -EINVAL;
			goto cleanup;
		}

		if (strcmp(t.tokens[2], "USER") == 0) {
			// DELETE USER srvmgrtest FOR *
			// AUTODROP DATABASE ??? - MAYBE PUT TO CONFIG FILE
			char qry[4096] = { 0 };
			if (t.numTokens < 5) {
				ret = -EINVAL;
				goto cleanup;
			}

			mysql_select_db(&sql, "mysql");

			if (strcmp(t.tokens[5], "*") == 0)
				snprintf(qry, sizeof(qry), "DELETE FROM user WHERE User = '%s'", t.tokens[3]);
			else
				snprintf(qry, sizeof(qry), "DELETE FROM user WHERE User = '%s' AND Host = '%s'",
					t.tokens[3], t.tokens[5]);

			if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
				DPRINTF("%s: Error occured on user deletion: %s\n", __FUNCTION__,
					mysql_error(&sql));
				ret = -EIO;
				goto cleanup;
			}

			snprintf(qry, sizeof(qry), "FLUSH PRIVILEGES");
			if (mysql_real_query(&sql, qry, strlen(qry)) != 0) {
				DPRINTF("%s: Error occured on flushing privileges: %s\n", __FUNCTION__,
					mysql_error(&sql));
				ret = -EIO;
				goto cleanup;
			}
		}
		else
			ret = -ENOTSUP;
	}
	else
		ret = -ENOTSUP;

cleanup:
	mysql_close(&sql);

	free(port);
	free(sock);
	free(host);
	free(user);
	free(pass);
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

