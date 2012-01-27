#ifndef MODULES_H_DEFINED
#define MODULES_H_DEFINED

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <libgen.h>

#define	BUFSIZE		8192

typedef struct tTokenizer {
	char **tokens;
	int numTokens;
} tTokenizer;

tTokenizer tokenize(char *string);
void free_tokens(tTokenizer t);

typedef struct tModule {
        char *ident;
	char *keyword;
        char *name;
	int port;
        void *handle;
} tModule;

tModule *modules;
int numModules;
int parentPid;

char* config_read(const char *filename, char *key);

#define SOCKET_PATH "/var/run/srvmgr-socket"
#define BANNER "Welcome to the Server Administration system!"
#define ADMINPWD "test" // IMPLEMENT BETTER ENCRYPTED FROM DATABASE

/* IPTables-related stuff */
#define IPT_PROTO_TCP	1
#define IPT_PROTO_UDP	2

#define IPT_TYPE_ACCEPT	1
#define IPT_TYPE_REJECT	2

#define IPT_CHAIN_NAME	"SRVMGR"

#define PORT_NONE	0
#define PORT_TCP(x)	(x << 16)
#define PORT_UDP(x)	(x)
#define PORT_BOTH(x)	( PORT_TCP(x) | PORT_UDP(x) )

#define GET_PORT_TCP(x)	(int)((x >> 16) & 0xFFFF)
#define GET_PORT_UDP(x)	(int)(x & 0xFFFF)
#define CMD_INSTALL	"/usr/bin/install"
#define CONFIG_INETD	"/etc/inetd.conf"

char *base64_decode(char *in);
char *process_read_handler(char *value);
char *process_handlers(char *path);

#endif
