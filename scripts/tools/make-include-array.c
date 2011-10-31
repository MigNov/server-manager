#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	if (argc < 3)
		return 1;

	int i = 0;
	char c, *name;
	FILE *fp, *fp2;

	fp = fopen(argv[1], "r");
	fp2 = fopen(argv[2], "w");

	name = strdup( (const char *)basename(argv[1]) );
	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '-')
			 name[i] = '_';
	}

	fprintf(fp2, "unsigned char %s[] = {\n\t", name);
	i = 0;
	while (!feof(fp)) {
		c = fgetc(fp);

		if ((i % 20 == 0) && (i > 0))
			fprintf(fp2, "\n\t");

		if (c == EOF) {
			fprintf(fp2, "0x%02x\n", '\n');
		}
		else {
			fprintf(fp2, "0x%02x, ", c);
			i++;
		}
	}

	fprintf(fp2, "};\n");
	return 0;
}

