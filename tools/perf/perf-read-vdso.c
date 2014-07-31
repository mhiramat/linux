#include <stdio.h>
#include <string.h>

#define VDSO__MAP_NAME "[vdso]"

static int find_vdso_map(void **start, void **end)
{
	FILE *maps;
	char line[128];
	int found = 0;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		fprintf(stderr, "vdso: cannot open maps\n");
		return -1;
	}

	while (!found && fgets(line, sizeof(line), maps)) {
		int m = -1;

		/* We care only about private r-x mappings. */
		if (2 != sscanf(line, "%p-%p r-xp %*x %*x:%*x %*u %n",
				start, end, &m))
			continue;
		if (m < 0)
			continue;

		if (!strncmp(&line[m], VDSO__MAP_NAME,
			     sizeof(VDSO__MAP_NAME) - 1))
			found = 1;
	}

	fclose(maps);
	return !found;
}

int main(void)
{
	void *start, *end;
	size_t size, written;

	if (find_vdso_map(&start, &end))
		return 1;

	size = end - start;

	while (size) {
		written = fwrite(start, 1, size, stdout);
		if (!written)
			return 1;
		start += written;
		size -= written;
	}

	if (fflush(stdout))
		return 1;

	return 0;
}
