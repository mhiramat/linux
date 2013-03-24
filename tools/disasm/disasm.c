/*
 * A Disassember
 * Written by Masami Hiramatsu <masami.hiramatsu@gmail.com>
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
static bool att = true;
static int lf_bytes = 7;
static char *filename;

static void usage(void)
{
	fprintf(stderr, "Usage: ldisasm [-6|-3] [-i|-a] [-l <NUM>] [-v] [file]\n");
	fprintf(stderr, "\t-6	64bit mode %s\n", (x86_64) ? "(default)" : "");
	fprintf(stderr, "\t-3	32bit mode %s\n", (x86_64) ? "" : "(default)");
	fprintf(stderr, "\t-i	Use Intel Syntax\n");
	fprintf(stderr, "\t-a	Use AT&T Syntax\n");
	fprintf(stderr, "\t-l <NUM>	Line feed with NUM bytes\n");
	fprintf(stderr, "\t-v	Increment verbosity\n");
	exit(1);
}

static void parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "63iavl:")) != -1) {
		switch (c) {
		case '6':
			x86_64 = true;
			break;
		case '3':
			x86_64 = false;
			break;
		case 'i':
			att = false;
			break;
		case 'a':
			att = true;
			break;
		case 'v':
			verbose++;
			break;
		case 'l':
			lf_bytes = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	if (lf_bytes < 0 || lf_bytes > MAX_INSN_SIZE) {
		fprintf(stderr, "Wrong Line feed bytes %d\n", lf_bytes);
		usage();
	}

	if (optind < argc)
		filename = strdup(argv[optind]);
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

static int read_instruction(FILE *fp, insn_byte_t *insn_buf, size_t size, char **line)
{
	char *buf = NULL, *p;
	size_t dummy;
	int i, ret;

	memset(insn_buf, 0, size);

	if (getline(&buf, &dummy, fp) < 0) {
		ret = -1;
		goto out;
	}

	if (buf[0] == '<') {
		ret = 0;
		goto out;
	}

	p = strchr(buf, ':');
	if (!p)
		p = buf;
	else
		p++;
	i = 0;
	while (i < size) {
		insn_buf[i++] = (insn_byte_t)strtoul(p, &p, 16);
		if (*p == '\0' || *p == '\n' || !isspace(*p))
			break;
	}
	*line = buf;
	return i;
out:
	*line  = NULL;
	return ret;
}

static int psnprintf(char **buf, size_t *len, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(*buf, *len, fmt, ap);
	va_end(ap);
	if (ret > 0 && ret < *len) {
		*buf += ret;
		*len -= ret;
	} else
		ret = -E2BIG;

	return ret;
}

/* Disassemble options */
#define DISASM_PR_ADDR	1	/* Print address */
#define DISASM_PR_RAW	2	/* Print raw code */
#define DISASM_PR_ALL	(DISASM_PR_ADDR | DISASM_PR_RAW)
#define DISASM_PR_INTEL	4	/* Print in intel syntax */

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
 * DISASM_PR_INTEL: show in intel syntax
 * Caller must initialize @insn but don't need to decode (ex insn_get_length).
 */
int snprint_assembly(char *buf, size_t len, struct insn *insn,
		     unsigned long real_addr, int opts)
{
	int i = 0, ret;
	unsigned char *fake_addr = (unsigned char *)insn->kaddr;

	insn_get_length(insn);
	if (!insn_complete(insn))
		return -EINVAL;

	if (opts & DISASM_PR_ADDR)	/* print real address */
		psnprintf(&buf, &len, "%lx: ", real_addr);

	if (opts & DISASM_PR_RAW) {	/* print raw instruction */
		for (i = 0; i < lf_bytes && i < insn->length; i++)
			psnprintf(&buf, &len, "%02x ", fake_addr[i]);
		psnprintf(&buf, &len, "%*s", 3 * (8 - i), " ");
	}

	insn->kaddr = (void *)real_addr;
	/* print assembly code */
	if (opts & DISASM_PR_INTEL)
		ret = disassemble(buf, len, insn, DISASM_SYNTAX_INTEL);
	else
		ret = disassemble(buf, len, insn, DISASM_SYNTAX_ATT);
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
			psnprintf(&buf, &len, "%02x ", fake_addr[i]);
		psnprintf(&buf, &len, "%02x\n", fake_addr[i]);
	}
	return 0;
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gelf.h>

Elf *elf_init(int fd)
{
	Elf *e;
	GElf_Ehdr ehdr;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Failed to init libelf.\n");
		return NULL;
	}

	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e == NULL) {
		fprintf(stderr, "Failed begin libelf session.\n");
		goto error;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		fprintf(stderr, "%s is not an ELF format file.\n", filename);
		goto error;
	}
	if (gelf_getehdr(e, &ehdr) == NULL) {
		fprintf(stderr, "Failed to get elf header.\n");
		goto error;
	}
	if (ehdr.e_machine != EM_386 && ehdr.e_machine != EM_X86_64) {
		fprintf(stderr, "%s is not intel x86 binary.\n", filename);
		goto error;
	}
	if (gelf_getclass(e) == ELFCLASS32)
		x86_64 = false;
	else
		x86_64 = true;

	return e;
error:
	if (e)
		elf_end(e);
	return NULL;
}

int disasm_elf_section(Elf *e, Elf_Scn *scn, GElf_Shdr *shdr)
{
	size_t n = 0, strndx;
	Elf_Data *data = NULL;
	char *p;
	struct insn insn;
	char buf[256];
	unsigned long addr;
	int ret;

	elf_getshdrstrndx(e, &strndx);
	p = elf_strptr(e, strndx, shdr->sh_name);
	printf("Section: \'%s\':\n", p);
	while (n < shdr->sh_size) {
		data = elf_getdata(scn, data);
		if (!data)
			break;
		p = data->d_buf;
		while (p < (char *)data->d_buf + data->d_size) {
			insn_init(&insn, p, x86_64);
			addr = shdr->sh_addr + p - (char *)data->d_buf;
			ret = snprint_assembly(buf, sizeof(buf), &insn, addr,
				DISASM_PR_ALL | (att ? 0 : DISASM_PR_INTEL));
			if (ret < 0) {
				printf("Error: reason %d\n", ret);
				if (verbose)
					dump_insn(stdout, &insn);
			} else {
				printf("%s", buf);
			}
			p += insn.length;
		}
	}
	return 0;
}

int disasm_elf(void)
{
	int fd, ret = 0;
	Elf *e;
	Elf_Scn *scn;
	GElf_Shdr shdr;

	fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s (%d)\n", filename, fd);
		ret = fd;
		goto error;
	}
	e = elf_init(fd);
	if (e == NULL) {
		ret = -EINVAL;
		goto error;
	}
	/* iterate sections */
	for (scn = elf_nextscn(e, NULL); scn; scn = elf_nextscn(e, scn)) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			fprintf(stderr, "Failed to get section header");
			goto error;
		}
		if (shdr.sh_flags & SHF_EXECINSTR) {
			ret = disasm_elf_section(e, scn, &shdr);
			if (ret < 0)
				break;
		}
	}
error:
	if (e)
		elf_end(e);
	if (fd >= 0)
		close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	insn_byte_t insn_buf[MAX_INSN_SIZE];
	struct insn insn;
	char buf[128], *lbuf, *tmp;
	const char *grp = NULL;
	unsigned long addr;
	int ret;
	int hint;

	parse_args(argc, argv);

	if (filename)
		return disasm_elf();

	while ((ret = read_instruction(stdin, insn_buf,
				       MAX_INSN_SIZE, &lbuf)) >= 0) {
		if (!lbuf)
			continue;
		if (lbuf[0] != '<')
			addr = strtoul(lbuf, NULL, 16);
		else
			addr = 0;

		insn_init(&insn, insn_buf, x86_64);
		ret = snprint_assembly(buf, sizeof(buf), &insn, addr,
			DISASM_PR_RAW | (att ? 0 : DISASM_PR_INTEL));
		if (ret < 0) {
			printf("Error: reason %d\n", ret);
			if (verbose)
				dump_insn(stdout, &insn);
		} else {
			tmp = strchr(lbuf, ':');
			if (tmp)
				printf("%.*s:\t", (int)(tmp - lbuf), lbuf);
			printf("%s", buf);
			free(lbuf);
			if (verbose >= 2) {
				printf("format: %s\n",
					get_mnemonic_format(&insn, &grp, &hint));
				if (grp)
					printf("format grp: %s\n", grp);
				dump_insn(stdout, &insn);
			}
		}
	}
	if (verbose)
		printf("ret = %d\n", ret);

	return 0;
}
