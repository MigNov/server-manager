#define DEBUG_MODULES
#include "manager.h"

#ifdef DEBUG_MODULES
#define DPRINTF(fmt, args...) \
do { printf("modules: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

int module_install(char *base_path, char *libname)
{
	int ret = -EINVAL;
	char path[BUFSIZE];
	void *lib = NULL;
	char *val = NULL;
	void *pInstall = NULL;
	typedef char* (*tInstallFunc) (char*);

	snprintf(path, sizeof(path), "%s/var", base_path);
	mkdir(path, 0755);

	snprintf(path, sizeof(path), "%s/var/%s-install-lock", base_path, basename(libname));
	if (access(path, R_OK) == 0) {
		DPRINTF("%s: Module %s already installed\n", __FUNCTION__, basename(libname));
		return 0;
	}

	lib = dlopen(libname, RTLD_LAZY);
	if (lib == NULL) {
		DPRINTF("%s: Cannot load library '%s'", __FUNCTION__, libname);
		return -EINVAL;
	}

	pInstall = dlsym(lib, "srvmgr_module_install");
	if (pInstall == NULL) {
		DPRINTF("%s: Cannot read installation function symbol from library %s\n",
				__FUNCTION__, libname);
		goto cleanup;
        }
	tInstallFunc fInstall = (tInstallFunc) pInstall;
	if (fInstall == NULL)
		goto cleanup;

	val = fInstall(base_path);
	if ((val != NULL) && (strcmp(val, "ERR") == 0)) {
		fprintf(stderr, "Warning: Cannot install module %s\n", basename(libname));
		ret = -EIO;
	}
	else {
		ret = users_add(val, val, NULL, NULL, NULL);
		if ((ret == 0) || (ret == -EEXIST)) {
			void *pPostInstall = NULL;

			ret = 0;
			pPostInstall = dlsym(lib, "srvmgr_module_install_post");
			if (pPostInstall != NULL) {
				typedef int (*tPostInstallFunc) (char*);
				tPostInstallFunc fPostInstall = (tPostInstallFunc) pPostInstall;
				if (fPostInstall != NULL)
					ret = fPostInstall(base_path);
			}

			if (ret == 0) {
				/* Touches the module lock file */
				close( open(path, O_WRONLY | O_CREAT, 0600) );
				ret = 0;
			}
		}
	}

cleanup:
	dlclose(lib);
	return ret;
}

int module_load(char *base_path, char *libname)
{
	int ret = -1;
	int port = -1;
	void *lib = NULL;
	void *pIdent = NULL;
	void *pKeyword = NULL;
	void *pGetPort = NULL;
	void *pIsApplicable = NULL;
	typedef char* (*tIdentFunc) (void);
	typedef char* (*tKeywordFunc) (void);
	typedef char* (*tInstallFunc) (void);
	typedef int   (*tIsApplicableFunc) (char*);

	if (module_install(base_path, libname) != 0) {
		DPRINTF("Error: Module %s installation failed\n", basename(libname));
		return -EINVAL;
	}

	lib = dlopen(libname, RTLD_LAZY);
	if (lib == NULL) {
		DPRINTF("%s: Cannot load library '%s'", __FUNCTION__, libname);
		goto done;
	}

	/* Get identification */
	pIdent = dlsym(lib, "srvmgr_module_identification");
	if (pIdent == NULL) {
		DPRINTF("%s: Cannot read identification symbol from library %s",
			__FUNCTION__, libname);
		goto cleanup;
	}
	tIdentFunc fIdent = (tIdentFunc) pIdent;
	if (fIdent == NULL)
		goto cleanup;

	/* Get keyword */
	pKeyword = dlsym(lib, "srvmgr_module_get_keyword");
	if (pKeyword == NULL) {
		DPRINTF("%s: Cannot read keyword symbol from library %s",
			__FUNCTION__, libname);
		goto cleanup;
	}
	tKeywordFunc fKeyword = (tKeywordFunc) pKeyword;
	if (fKeyword == NULL)
		goto cleanup;

	/* Is module applicable? */
	pIsApplicable = dlsym(lib, "srvmgr_module_is_applicable");
	if (pIsApplicable == NULL) {
		DPRINTF("%s: Cannot read is_applicable symbol from library %s",
			__FUNCTION__, libname);
		goto cleanup;
	}
	tIsApplicableFunc fIsApplicable = (tIsApplicableFunc) pIsApplicable;
	if (fIsApplicable == NULL)
		goto cleanup;

	/* Here 1 means true, i.e. module is applicable */
	if ( fIsApplicable(base_path) != 1 )
		goto cleanup;

	/* Get port if applicable */
	pGetPort = dlsym(lib, "srvmgr_module_get_port");
	if (pGetPort != NULL) {
		typedef int (*tGetPortFunc) (void);

		tGetPortFunc fGetPort = (tGetPortFunc) pGetPort;
		port = fGetPort();
	}

	/* Put module into the module pool */
	if (modules == NULL)
		modules = (tModule *)malloc( sizeof(tModule) );
	else
		modules = (tModule *)realloc( modules, (numModules + 1) * sizeof(tModule) );

	modules[numModules].ident = strdup( fIdent() );
	modules[numModules].keyword = strdup( fKeyword() );
	modules[numModules].port = port;
	modules[numModules].name = strdup( libname );
	modules[numModules].handle = lib;
	numModules++;

	ret = 0;
	goto done;

cleanup:
	dlclose(lib);
done:
	return ret;
}

int module_process_by_handle(void *lib, char *base_path, char *data, int authorized)
{
	void *pProcess = NULL;
	typedef int (*tProcessFunc) (char *base_path, char *data, int authorized);

	pProcess = dlsym(lib, "srvmgr_module_run");
	if (pProcess == NULL)
		return -1;

	tProcessFunc fProcess = (tProcessFunc) pProcess;
	return fProcess(base_path, data, authorized);
}

int module_process_all(char *base_path, char *data, int authorized)
{
	int ret = -ENOENT, i;

	if (numModules == 0)
		return ret;

	for (i = 0; i < numModules; i++) {
		if ((ret = module_process_by_handle(modules[i].handle, base_path, data,
			authorized)) != -ENOTSUP)
			return ret;
	}

	return ret;
}

int module_duplicates_exist(void)
{
	int i, j, ret = 0;

	for (i = 0; i < numModules; i++) {
		for (j = 0; j < numModules; j++) {
			if ((strcmp(modules[i].keyword, modules[j].keyword) == 0)
				&& (i != j)) {
				fprintf(stderr, "Warning: Modules %s and %s handles the same keyword: %s\n",
					basename(modules[i].name), basename(modules[j].name), modules[i].keyword);
				ret = 1;
			}
		}
	}

	return ret;
}

void module_dump(void)
{
	int i;

	if (numModules == 0)
		return;

	DPRINTF("-----\n");
	DPRINTF("Dumping data for %d module(s):\n", numModules);
	for (i = 0; i < numModules; i++) {
		DPRINTF("Module #%d:\n", i+1);
		DPRINTF("\tHandle: 0x%p\n", modules[i].handle);
		DPRINTF("\tFilename: %s\n", basename(modules[i].name));
		DPRINTF("\tIdentification: %s\n", modules[i].ident);
		DPRINTF("\tKeyword: %s\n", modules[i].keyword);

		if (GET_PORT_TCP(modules[i].port))
			DPRINTF("\tTCP Port: %d\n", GET_PORT_TCP(modules[i].port));
		if (GET_PORT_UDP(modules[i].port))
			DPRINTF("\tUDP Port: %d\n", GET_PORT_UDP(modules[i].port));
	}
	DPRINTF("-----\n");
}

void modules_free(void)
{
	int i;

	if (numModules == 0)
		return;

	for (i = 0; i < numModules; i++) {
		dlclose(modules[i].handle);
		free(modules[i].ident);
		modules[i].ident = NULL;
		free(modules[i].name);
		modules[i].name = NULL;
		free(modules[i].keyword);
		modules[i].keyword = NULL;
	}

	numModules = 0;

	free(modules);
}

int modules_load_all(char *base_path, char *directory)
{
	char filename[BUFSIZE];
	struct dirent *entry;
	DIR *d;

	d = opendir(directory);
	if (d == NULL)
		return -1;

	while ((entry = readdir(d)) != NULL) {
		if (strstr(entry->d_name, ".so") != NULL) {
			snprintf(filename, sizeof(filename), "%s/%s", directory, entry->d_name);
			module_load(base_path, filename);
		}
	}

	closedir(d);

	return module_duplicates_exist();
}

int modules_init(void)
{
	modules = NULL;
	numModules = 0;
}

int modules_get_active(void)
{
	return numModules;
}

#if 0
int main()
{
	modules = NULL;
	numModules = 0;

	atexit(modules_free);

	modules_load_all(".");
	module_dump();

	module_process_all("SCM-GIT CREATE REPO test FOR domain1", 1);

	return 0;
}
#endif
