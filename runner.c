#define DEBUG_RUNNER

#include "manager.h"

#ifdef DEBUG_RUNNER
#define DPRINTF(fmt, args...) \
do { printf("runner: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

void exitFunc(void)
{
	if ((parentPid != getpid()) || (getuid() != 0))
		return;

	firewall_srvmgr_enable( 0 );
	firewall_srvmgr_chain_delete();
	firewall_chain_delete();

	firewall_save( 1 );

	modules_free();
	DPRINTF("Terminating ...\n");
}

void exitFunc2(int sig)
{
	exitFunc();
	exit(0);
}

void firewall_init(void)
{
	int i;

	firewall_srvmgr_chain_delete();
	firewall_ensure_chain_exist();

	for (i = 0; i < numModules; i++) {
		if (GET_PORT_TCP(modules[i].port) > 0)
			firewall_rule_insert(GET_PORT_TCP(modules[i].port), IPT_PROTO_TCP, IPT_TYPE_ACCEPT);
		if (GET_PORT_UDP(modules[i].port) > 0)
			firewall_rule_insert(GET_PORT_UDP(modules[i].port), IPT_PROTO_UDP, IPT_TYPE_ACCEPT);
	}

	//firewall_rule_insert(port, IPT_PROTO_TCP | IPT_PROTO_UDP, IPT_TYPE_ACCEPT);

	if (firewall_srvmgr_chain_enabled() != 1) {
		firewall_srvmgr_enable( 1 );
	}

	firewall_save( 1 );
}

int main(int argc, char *argv[])
{
	int ret;
	char modPath[BUFSIZE];
	char *arg0 = strdup(argv[0]);
	char *dir = dirname(arg0);

	atexit(exitFunc);
	modules_init();

	signal(SIGINT, &exitFunc2);

	parentPid = getpid();
	DPRINTF("Parent PID is %d\n", parentPid);

	//printf("%d\n", users_add("mix", "mig", NULL, NULL, NULL));
	//return 0;

	if (argc == 1) {
		snprintf(modPath, sizeof(modPath), "%s/modules", dir);
		if ((ret = modules_load_all(dir, modPath)) != 0) {
			if (ret < 0) {
				DPRINTF("%s: Cannot load modules\n", __FUNCTION__);
				return 1;
			}
			char config_file[BUFSIZE];

			snprintf(config_file, sizeof(config_file), "%s/manager.conf", dir);
			if (access(config_file, R_OK) == 0) {
				char *val = config_read(config_file, "module.duplicate_handling");
				if (val != NULL) {
					if (strcmp(val, "fatal") == 0) {
						fprintf(stderr, "Module duplicate set to be fatal. Exiting...\n");
						free(val);
						return 1;
					}
					else
					if (strcmp(val, "warn") != 0) {
						fprintf(stderr, "Error: Invalid value for module.duplicate_handling"
							" in config file (%s).\n", basename(config_file));
						return 1;
					}

					free(val);
				}
			}
		}
		module_dump();

		if (!modules_get_active()) {
			DPRINTF("No active module found, terminating ...\n");
			return 2;
		}

		firewall_init();

		DPRINTF("Bind result: %d\n", socket_bind(dir, SOCKET_PATH));
	}
	else
		if (argc == 2) {
			DPRINTF("Write result: %d\n", socket_write(SOCKET_PATH, ADMINPWD, argv[1]));
	}

	return 0;
}

