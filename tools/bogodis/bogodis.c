/* bogodis - A Bogus Disassember
 * Written by Masami Hiramatsu <masami.hiramatsu@gmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#define _LINUX_CTYPE_H	/* Dummy for avoiding build error */
#define _LINUX_KERNEL_H	/* Ditto */
#include <errno.h>
#define BUG_ON(a)	\
	do { fprintf(stderr, "BUG at %s:%d\n", __FILE__, __LINE__); exit(1); } while (1)

/* These are for compiling instruction decoder in user space */
#define unlikely(cond) (cond)

#include <asm/insn.h>
#include <asm/disasm.h>

/* Decoder code */
#include <inat.c>
#include <insn.c>

/* Disassembler code */
#include <mnemonic.c>
#include <disasm.c>

static int verbose;
static bool x86_64 = (sizeof(long) == 8);

static void usage(void)
{
	fprintf(stderr, "Usage: bogodis [-6|-3] [-v]\n");
	fprintf(stderr, "\t-6	64bit mode %s\n", (x86_64) ? "(default)" : "");
	fprintf(stderr, "\t-3	32bit mode %s\n", (x86_64) ? "" : "(default)");
	fprintf(stderr, "\t-v	Increment verbosity\n");
	exit(1);
}

static void parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "63v")) != -1) {
		switch (c) {
		case '6':
			x86_64 = true;
			break;
		case '3':
			x86_64 = false;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
}

static void dump_field(FILE *fp, const char *name, const char *indent,
		       struct insn_field *field)
{
	fprintf(fp, "%s.%s = {\n", indent, name);
	fprintf(fp, "%s\t.value = %d, bytes[] = {%x, %x, %x, %x},\n",
		indent, field->value, field->bytes[0], field->bytes[1],
		field->bytes[2], field->bytes[3]);
	fprintf(fp, "%s\t.got = %d, .nbytes = %d},\n", indent,
		field->got, field->nbytes);
}

static void dump_insn(FILE *fp, struct insn *insn)
{
	fprintf(fp, "Instruction = {\n");
	dump_field(fp, "prefixes", "\t",	&insn->prefixes);
	dump_field(fp, "rex_prefix", "\t",	&insn->rex_prefix);
	dump_field(fp, "vex_prefix", "\t",	&insn->vex_prefix);
	dump_field(fp, "opcode", "\t",		&insn->opcode);
	dump_field(fp, "modrm", "\t",		&insn->modrm);
	dump_field(fp, "sib", "\t",		&insn->sib);
	dump_field(fp, "displacement", "\t",	&insn->displacement);
	dump_field(fp, "immediate1", "\t",	&insn->immediate1);
	dump_field(fp, "immediate2", "\t",	&insn->immediate2);
	fprintf(fp, "\t.attr = %x, .opnd_bytes = %d, .addr_bytes = %d,\n",
		insn->attr, insn->opnd_bytes, insn->addr_bytes);
	fprintf(fp, "\t.length = %d, .x86_64 = %d, .kaddr = %p}\n",
		insn->length, insn->x86_64, insn->kaddr);
}

static int read_instruction(FILE *fp, insn_byte_t *insn_buf, size_t size)
{
	char *buf = NULL, *p;
	size_t dummy;
	int i;

	memset(insn_buf, 0, size);

	if (getline(&buf, &dummy, fp) < 0)
		return -errno;
	p = buf;
	i = 0;
	while (i < size) {
		insn_buf[i++] = (insn_byte_t)strtoul(p, &p, 16);
		if (*p == '\0' || *p == '\n' || !isspace(*p))
			break;
	}
	free(buf);
	return i;
}

/* Disassemble options */
#define DISASM_PR_ADDR	1	/* Print address */
#define DISASM_PR_RAW	2	/* Print raw code */
#define DISASM_PR_ALL	(DISASM_PR_ADDR | DISASM_PR_RAW)

/**
 * snprint_assembly() - Disassemble given instruction with headers
 * @buf:	A buffer in which assembly code is stored
 * @len:	The size of @buf
 * @insn:	An instruction which will be disassembled
 * @opts:	Options
 *
 * This disassembles given instruction and put it into buffer with
 * some optional information. Available option flagss are;
 * DISASM_PR_ADDR: the address of given instruction is added.
 * DISASM_PR_RAW:  the raw bytes of given instruction are added.
 * Caller must initialize @insn but don't need to decode (ex insn_get_length).
 */
int snprint_assembly(char *buf, size_t len, struct insn *insn,
		     unsigned long real_addr, int opts)
{
	int i = 0, ret;

	insn_get_length(insn);
	if (!insn_complete(insn))
		return -EINVAL;

	if (opts & DISASM_PR_ADDR)	/* print real address */
		psnprintf(&buf, &len, "%lx: ", real_addr);

	if (opts & DISASM_PR_RAW) {	/* print raw instruction */
		for (i = 0; i < MAX_INSN_SIZE / 2 && i < insn->length; i++)
			psnprintf(&buf, &len, "%02x ", insn->kaddr[i]);
		if (i != MAX_INSN_SIZE / 2)
			psnprintf(&buf, &len, "%*s",
				3 * (MAX_INSN_SIZE / 2 - i), " ");
	}

	/* print assembly code */
	ret = disassemble(buf, len, insn);
	if (ret < 0)
		return ret;
	len -= ret;
	buf += ret;
	psnprintf(&buf, &len, "\n");

	/* print rest of raw instruction if exist */
	if ((opts & DISASM_PR_RAW) && (i < insn->length)) {
		if (opts & DISASM_PR_ADDR) /* print real address */
			psnprintf(&buf, &len, "%lx: ", real_addr + i);
		for (; i < insn->length - 1; i++)
			psnprintf(&buf, &len, "%02x ", insn->kaddr[i]);
		psnprintf(&buf, &len, "%02x\n", insn->kaddr[i]);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	insn_byte_t insn_buf[MAX_INSN_SIZE];
	struct insn insn;
	char buf[128];
	const char *grp;
	int ret;

	parse_args(argc, argv);

	while ((ret = read_instruction(stdin, insn_buf, MAX_INSN_SIZE)) > 0) {
		insn_init(&insn, insn_buf, x86_64);
		ret = snprint_assembly(buf, sizeof(buf), &insn, 0, DISASM_PR_ALL);
		if (ret < 0) {
			printf("Error: reason %d\n", ret);
			if (verbose)
				dump_insn(stdout, &insn);
		} else {
			printf("%s", buf);
			if (verbose >= 2) {
				printf("format: %s\n",
					get_mnemonic_format(&insn, &grp));
				dump_insn(stdout, &insn);
			}
		}
	}
	if (verbose)
		printf("ret = %d\n", ret);

	return 0;
}
