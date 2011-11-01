#define MODULE_IDENTIFICATION	"MAIL Sendmail module"
#define MODULE_KEYWORD          "MAIL"

#define DEBUG_MOD_SENDMAIL

#include "../manager.h"

#ifdef DEBUG_MOD_SENDMAIL
#define DPRINTF(fmt, args...) \
do { printf("mod_sendmail: " fmt , ##args); } while (0)
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

int srvmgr_module_is_applicable(char *base_path)
{
	return 0;
}

char *srvmgr_module_install(void)
{
	return strdup( "ERR" );
}

int srvmgr_module_run(char *base_path, char *data, int authorized)
{
	if (strncmp(data, MODULE_KEYWORD, strlen(MODULE_KEYWORD)) != 0)
		return -ENOTSUP;

        DPRINTF("[%s] Input data: '%s' ( user %s authorized )\n", MODULE_IDENTIFICATION,
			data, authorized ? "is" : "NOT");

	return 0;
}

