#define DEBUG_CONFIG

#include "manager.h"

#ifdef DEBUG_CONFIG
#define DPRINTF(fmt, args...) \
do { printf("config: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif


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

