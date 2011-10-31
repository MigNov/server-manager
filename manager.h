#ifndef MODULES_H_DEFINED
#define MODULES_H_DEFINED

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

#define	BUFSIZE		8192

typedef struct tModule {
        char *ident;
	char *keyword;
        char *name;
	int port;
        void *handle;
} tModule;

tModule *modules;
int numModules;

char* config_read(const char *filename, char *key);

#define SOCKET_PATH "/home/mig/Work/Interest/myPackages/server-manager/tmp/server-socket"
#define BANNER "Welcome to the Server Administration system!"
#define ADMINPWD "test" // IMPLEMENT BETTER ENCRYPTED FROM DATABASE

/* IPTables-related stuff */
#define IPT_PROTO_TCP	1
#define IPT_PROTO_UDP	2

#define IPT_TYPE_ACCEPT	1
#define IPT_TYPE_REJECT	2

#define IPT_CHAIN_NAME	"SRVMGR"

#endif
