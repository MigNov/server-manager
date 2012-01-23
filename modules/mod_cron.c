#define MODULE_IDENTIFICATION	"CRON Module"
#define MODULE_KEYWORD		"CRON"
#define MODULE_PORT		0
#define DEBUG_MOD_CRON

#include "../manager.h"

#ifdef DEBUG_MOD_CRON
#define DPRINTF(fmt, args...) \
do { printf("mod_cron: " fmt , ##args); } while (0)
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

char *srvmgr_module_install(void)
{
	return NULL;
}

int cmd_requires_authorization(char *cmd)
{
	return (strcmp(cmd, "LIST") != 0);
}

int cron_do_listing(char *username, char *filename)
{
	char tmp[4096] = { 0 };
	char cmd[1024] = { 0 };
	FILE *fp = NULL;
	int ret = 0;

	snprintf(cmd, sizeof(cmd), "crontab -u %s -l 2>&1", username);
	DPRINTF("%s: Spawning '%s'\n", __FUNCTION__, cmd);
	fp = popen(cmd, "r");
	if (fp == NULL)
		ret = -EIO;
	else {
		FILE *outfile = fopen(filename, "w");
		if (outfile == NULL)
			ret = -EPERM;
		else {
			while (!feof(fp)) {
				memset(tmp, 0, sizeof(tmp));
				fgets(tmp, sizeof(tmp), fp);

				if (strlen(tmp) > 0) {
					if (strstr(tmp, "crontab") != NULL) {
						fclose(outfile);
						outfile = NULL;
						unlink(filename);
						ret = -ENOENT;
						break;
					}

					fputs(tmp, outfile);
				}
			}
			if (outfile != NULL)
				fclose(outfile);

			if (ret == 0)
				DPRINTF("%s: File saved to %s\n", __FUNCTION__, filename);
			else
				DPRINTF("%s: Cron output error. Possibly no crontab for user %s available\n",
					__FUNCTION__, username);
		}
		fclose(fp);
	}

	return ret;
}

int process_commands(char *config_file, int authorized, tTokenizer t)
{
	char tmp[4096] = { 0 };
	char cmd[1024] = { 0 };
	int  ret = 0;
	FILE *fp = NULL;

	if (t.numTokens < 2) {
		ret = -EIO;
		goto cleanup;
	}

	if (cmd_requires_authorization(t.tokens[1]) && !authorized) {
		ret = -EACCES;
		goto cleanup;
	}

	if (strcmp(t.tokens[1], "LIST") == 0) {
		if (t.numTokens < 4) {
			ret = -EINVAL;
			goto cleanup;
		}

		ret = cron_do_listing(t.tokens[2], t.tokens[3]);
	}
	else
	if (strcmp(t.tokens[1], "ADD") == 0) {
		if (t.numTokens < 9) {
			ret = -EINVAL;
			goto cleanup;
		}
		else {
			int i;
			FILE *fp = NULL;
			char tmp[] = "/tmp/srvmgr-cron.XXXXXX";
			mkstemp(tmp);

			cron_do_listing(t.tokens[2], tmp);
			DPRINTF("%s: Saved to %s\n", __FUNCTION__, tmp);

			fp = fopen(tmp, "a");
			if (fp == NULL)
				ret = -EPERM;
			else {
				if (!file_check_executable(t.tokens[8])) {
					ret = -ENOENT;
					goto cleanup;
				}
				for (i = 3; i <= 8; i++)
					fprintf(fp, "%s ", t.tokens[i]);
				fprintf(fp, "\n");
				fclose(fp);

				snprintf(cmd, sizeof(cmd), "crontab -u %s %s", t.tokens[2], tmp);
				system(cmd);

				unlink(tmp);
			}
		}
	}
	else
	if ((strcmp(t.tokens[1], "DELETE") == 0) || (strcmp(t.tokens[1], "REMOVE") == 0)) {
		if (t.numTokens < 9) {
			ret = -EINVAL;
			goto cleanup;
		}
		else {
			int i;
			FILE *fp = NULL;
			char data[4096] = { 0 };
			char tmp[] = "/tmp/srvmgr-cron.XXXXXX";
			char tmp2[] = "/tmp/srvmgr-cron-out.XXXXXX";
			char packet[1024] = { 0 };
			mkstemp(tmp);
			mkstemp(tmp2);

			cron_do_listing(t.tokens[2], tmp);
			DPRINTF("%s: Saved to %s\n", __FUNCTION__, tmp);

			for (i = 3; i < 8; i++) {
				strcat(packet, t.tokens[i]);
				strcat(packet, " ");
			}
			strcat(packet, t.tokens[8]);

			DPRINTF("%s: Packet formatted to '%s'\n", __FUNCTION__, packet);

			fp = fopen(tmp, "r");
			if (fp == NULL) {
				ret = -EACCES;
				DPRINTF("%s: Cannot open %s for reading\n", __FUNCTION__, tmp);
			}
			else {
				FILE *fp2 = fopen(tmp2, "w");
				if (fp2 == NULL) {
					ret = -EPERM;
					DPRINTF("%s: Cannot open %s for writing\n", __FUNCTION__, tmp2);
				}
				else {
					int deleted = 0;
					while (!feof(fp)) {
						memset(data, 0, sizeof(data));
						fgets(data, sizeof(data), fp);

						if (data[ strlen(data) - 1 ] == '\n')
							data[ strlen(data) - 1 ] = 0;
						if (data[ strlen(data) - 1] == ' ')
							data[ strlen(data) - 1 ] = 0;

						if (strlen(data) == 0)
							break;

						DPRINTF("%s: Read '%s'\n", __FUNCTION__, data);

						if (strcmp(data, packet) != 0)
							fprintf(fp2, "%s\n", data);
						else
							deleted = 1;
					}
					fclose(fp2);

					if (deleted) {
						snprintf(cmd, sizeof(cmd), "crontab -u %s %s", t.tokens[2], tmp2);
						DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
						system(cmd);
					}
					else
						ret = -EINVAL;

					unlink(tmp2);
				}
				fclose(fp);
				unlink(tmp);
			}
		}
	}
	else
	if (strcmp(t.tokens[1], "TRUNCATE") == 0) {
		if (t.numTokens < 3) {
			return -EINVAL;
			goto cleanup;
		}

		snprintf(cmd, sizeof(cmd), "crontab -u %s -r", t.tokens[2]);
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		system(cmd);
	}
	else
		ret = -ENOTSUP;

cleanup:
	return ret;
}

int srvmgr_module_is_applicable(char *base_path)
{
	return 1;
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

