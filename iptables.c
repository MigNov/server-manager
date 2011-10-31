#define	IPTABLES_BINARY		"/sbin/iptables"
#define IPTABLES_CONFIG		"/etc/sysconfig/iptables"
#define IPTABLES_SERVICE	"service iptables"
#define DEBUG_IPTABLES

#include "manager.h"

#ifdef DEBUG_IPTABLES
#define DPRINTF(fmt, args...) \
do { printf("iptables: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

int firewall_ensure_chain_exist(void)
{
	char cmd[BUFSIZE];

	snprintf(cmd, sizeof(cmd), "%s -N %s 2> /dev/null > /dev/null", IPTABLES_BINARY, IPT_CHAIN_NAME);
	return WEXITSTATUS(system(cmd));
}

int firewall_chain_delete(void)
{
	char cmd[BUFSIZE];

	snprintf(cmd, sizeof(cmd), "%s -X %s 2> /dev/null > /dev/null", IPTABLES_BINARY, IPT_CHAIN_NAME);
	return WEXITSTATUS(system(cmd));
}

int firewall_srvmgr_enable(int enable)
{
	int ret;
	char cmd[BUFSIZE];

	snprintf(cmd, sizeof(cmd), "%s -%c INPUT --jump %s 2> /dev/null >/dev/null", IPTABLES_BINARY, (enable) ? 'I' : 'D',
		IPT_CHAIN_NAME);

	DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);

	if ((ret = WEXITSTATUS(system(cmd))) != 0)
		return ret;

	firewall_save();
	return ret;
}

int firewall_srvmgr_chain_enabled(void)
{
	int ret = 0;
	FILE *fp;
	char s[1024] = { 0 };
	char s1[1024] = { 0 };

	fp = fopen(IPTABLES_CONFIG, "r");
	if (fp == NULL)
		return -EACCES;

	snprintf(s1, sizeof(s1), "-A INPUT -j %s", IPT_CHAIN_NAME);

	while (!feof(fp)) {
		fgets(s, sizeof(s), fp);

		if (strncmp(s, s1, strlen(s1)) == 0)
			ret = 1;
	}

	fclose(fp);
	return ret;
}

int firewall_srvmgr_chain_delete(void)
{
	FILE *fp, *fp2;
	char s[2048] = { 0 };
	char tmp[] = "/tmp/srvmgr-iptables.XXXXXX";

	mkstemp(tmp);

	fp = fopen(IPTABLES_CONFIG, "r");
	if (fp == NULL)
		return -EACCES;

	fp2 = fopen(tmp, "w");
	if (fp2 == NULL)
		return -EACCES;

	while (!feof(fp)) {
		fgets(s, sizeof(s), fp);

		if (strncmp(s, "-A SRVMGR", 9) != 0)
			fputs(s, fp2);
	}

	fclose(fp2);
	fclose(fp);

	snprintf(s, sizeof(s), "mv %s %s > /dev/null 2> /dev/null", tmp, IPTABLES_CONFIG);
	DPRINTF("%s: Running '%s'\n", __FUNCTION__, s);
	system(s);

	firewall_restart();

	return 0;
}

int firewall_rule_insert(int port, int proto, int type)
{
	char cmd[BUFSIZE];

	if ((type != IPT_TYPE_ACCEPT) && (type != IPT_TYPE_REJECT)) {
		DPRINTF("%s: Invalid rule type\n", __FUNCTION__);
		return -ENOTSUP;
	}

	if (proto & IPT_PROTO_TCP) {
		snprintf(cmd, sizeof(cmd), "%s -I %s -p tcp --dport %d -j %s", IPTABLES_BINARY, IPT_CHAIN_NAME,
			port, (type == IPT_TYPE_ACCEPT) ? "ACCEPT" : "REJECT");
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		system(cmd);
	}

	if (proto & IPT_PROTO_UDP) {
		snprintf(cmd, sizeof(cmd), "%s -I %s -p udp --dport %d -j %s", IPTABLES_BINARY, IPT_CHAIN_NAME,
			port, (type == IPT_TYPE_ACCEPT) ? "ACCEPT" : "REJECT");
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		system(cmd);
	}

	return 0;
}

void firewall_rule_delete(int port, int proto, int type)
{
	char cmd[BUFSIZE];

	if (proto & IPT_PROTO_TCP) {
		snprintf(cmd, sizeof(cmd), "%s -D %s -p tcp --dport %d -j %s", IPTABLES_BINARY, IPT_CHAIN_NAME,
			port, (type == IPT_TYPE_ACCEPT) ? "ACCEPT" : "REJECT");
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		system(cmd);
	}

	if (proto & IPT_PROTO_UDP) {
		snprintf(cmd, sizeof(cmd), "%s -D %s -p udp --dport %d -j %s", IPTABLES_BINARY, IPT_CHAIN_NAME,
			port, (type == IPT_TYPE_ACCEPT) ? "ACCEPT" : "REJECT");
		DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);
		system(cmd);
	}
}

int firewall_restart(void)
{
	char cmd[BUFSIZE];
	snprintf(cmd, sizeof(cmd), "%s restart 2>/dev/null >/dev/null", IPTABLES_SERVICE);
	DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);

	return WEXITSTATUS(system(cmd));
}

int firewall_save(int restart)
{
	int ret;
	char cmd[BUFSIZE];

	snprintf(cmd, sizeof(cmd), "%s save 2>/dev/null >/dev/null", IPTABLES_SERVICE);
	DPRINTF("%s: Running '%s'\n", __FUNCTION__, cmd);

	ret = WEXITSTATUS(system(cmd));
	if ((ret != 0) && (restart))
		return ret;

	return firewall_restart();
}

