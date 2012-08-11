/*
 * EID splitter thing.
 *
 * Licensed under GPL v3.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void
dump_eid_data(FILE * fp, int isz, int eidc, char *prefix)
{
	FILE *fp_o;
	char *filename, *buf;
	int ret, sz;

	printf("dumping EID%d from eEID at %p, size %d (%x)..\n",
	       eidc, fp, isz, isz);

	buf = (char *)malloc(isz + 1);
	filename = (char *)malloc(strlen(prefix) + 2);

	if (buf == NULL) {
		perror("malloc");
		exit(1);
	};

	sz = fread(buf, isz, 1, fp);
	sprintf(filename, "%s%d", prefix, eidc);
	fp_o = fopen(filename, "wb");
	ret = fwrite(buf, isz, 1, fp_o);

	if (ret != sz) {
		perror("fwrite");
		exit(1);
	};

	free(buf);
}

int main(int argc, char **argv)
{
	FILE *fp;
	char *prefix = "eid";

	fp = fopen(argv[1], "rb");
	if (fp == NULL) {
usage:
		printf("usage: %s <eEID> <EID name prefix>\n", argv[0]);
		exit(1);
	}

	if (argc == 2 && argv[2] != NULL) {
		prefix = argv[2];
		goto usage;
	}

	fseek(fp, 0x70, SEEK_SET);

	if (prefix != NULL) {
		dump_eid_data(fp, 2144, 0, prefix);
		dump_eid_data(fp, 672, 1, prefix);
		dump_eid_data(fp, 1840, 2, prefix);
		dump_eid_data(fp, 256, 3, prefix);
		dump_eid_data(fp, 48, 4, prefix);
		dump_eid_data(fp, 2560, 5, prefix);
	}
	return 0;
}
