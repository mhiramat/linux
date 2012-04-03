/*
 * Disasm.c -- the core of bogus disassembler code
 * Written by Masami Hiramatsu <masami.hiramatsu@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#ifdef __KERNEL__
#include <linux/kallsyms.h>
#endif

#include <asm/disasm.h>

#define X86_LEA_OPCODE 0x8d

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

#ifdef __KERNEL__
/* Print address with symbol */
static int psnprint_symbol(char **buf, size_t *len, unsigned long addr)
{
	unsigned long offs;
	char func[KSYM_NAME_LEN];
	char *modname;
	int ret;

	ret = psnprintf(buf, len, "%lx", addr);
	if (!kallsyms_lookup(addr, NULL, &offs, &modname, func))
		return ret;

	psnprintf(buf, len, " <%s", func);
	if (offs)
		psnprintf(buf, len, "+0x%lx", offs);
	if (modname)
		psnprintf(buf, len, " [%s]", modname);

	return psnprintf(buf, len, ">");
}
#else
static int psnprint_symbol(char **buf, size_t *len, unsigned long addr)
{
	return psnprintf(buf, len, "%lx", addr);
}
#endif

/* Operand classifiers */
static bool operand_is_register(const char *p)
{
	return !isupper(*p);
}

static bool operand_is_imm(const char *p)
{
	return strchr("AIJO", *p) != NULL;
}

static bool operand_is_gp_reg(const char *p)
{
	return *p == 'G';
}

static bool operand_is_ctl_reg(const char *p)
{
	return *p == 'C';
}

static bool operand_is_dbg_reg(const char *p)
{
	return *p == 'D';
}

static bool operand_is_seg_reg(const char *p)
{
	return *p == 'S';
}

static bool operand_is_flags(const char *p)
{
	return *p == 'F';
}

static bool operand_is_fixmem(const char *p)
{
	return *p == 'X' || *p == 'Y';
}

static bool operand_is_mmx_rm(const char *p)
{
	return *p == 'N' || *p == 'Q';
}

static bool operand_is_xmm_rm(const char *p)
{
	return *p == 'U' || *p == 'W';
}

static bool operand_is_memreg(const char *p)
{
	return *p == 'E' || *p == 'M' || *p == 'R' || operand_is_mmx_rm(p) || operand_is_xmm_rm(p);
}

static bool operand_is_mmxreg(const char *p)
{
	return *p == 'P';
}

static bool operand_is_xmmreg(const char *p)
{
	return *p == 'V';
}

static bool operand_is_gpr_vex(const char *p)
{
	return *p == 'B';
}

static bool operand_is_xmm_vex(const char *p)
{
	return *p == 'H';
}

static bool operand_is_xmm_imm(const char *p)
{
	return *p == 'L';
}

/* register maps */
const char *gpreg_map[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
const char *gpreg8_map[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
const char *gpreg8_map2[8] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
const char *segreg_map[8] = {"es", "cs", "ss", "ds", "fs", "gs", "(bad)", "(bad)"};
const char *gprea16_map[8] = {"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"};

static unsigned int insn_field_get_uval(struct insn_field *field)
{
	switch (field->nbytes) {
	case 1:
		return field->bytes[0];
	case 2:
		return (unsigned short)field->value;
	default:
		return (unsigned int)field->value;
	}
}

static int bad_modrm_operand(char c, int mod)
{
	return ((c == 'R' || c == 'N' || c == 'U') && mod != 3) || (c == 'M' && mod == 3);
}

/* Print General Purpose Registers by number */
static int psnprint_gpr8(char **buf, size_t *len, int idx)
{
	if (idx < 8)
		return psnprintf(buf, len, "%%%s", gpreg8_map[idx]);
	else
		return psnprintf(buf, len, "%%r%db", idx);
}

/* Special exception for reg bits encoding with rex prefix */
static int psnprint_gpr8_rex(char **buf, size_t *len, int idx)
{
	if (idx < 8)
		return psnprintf(buf, len, "%%%s", gpreg8_map2[idx]);
	else
		return psnprintf(buf, len, "%%r%db", idx);
}

static int psnprint_gpr16(char **buf, size_t *len, int idx)
{
	if (idx < 8)
		return psnprintf(buf, len, "%%%s", gpreg_map[idx]);
	else
		return psnprintf(buf, len, "%%r%dw", idx);
}

static int psnprint_gpr32(char **buf, size_t *len, int idx)
{
	if (idx < 8)
		return psnprintf(buf, len, "%%e%s", gpreg_map[idx]);
	else
		return psnprintf(buf, len, "%%r%dd", idx);
}

static int psnprint_gpr64(char **buf, size_t *len, int idx)
{
	if (idx < 8)
		return psnprintf(buf, len, "%%r%s", gpreg_map[idx]);
	else
		return psnprintf(buf, len, "%%r%d", idx);
}

static int psnprint_xmmreg(char **buf, size_t *len, const char *opnd,
			   struct insn *insn, int idx)
{
	int c = 'x';
	if (opnd[1] == 'q' ||	/* Should be Quad-Quad(qq)word */
	    (opnd[1] != 's' && insn_vex_l_bit(insn)))
		c = 'y';

	return psnprintf(buf, len, "%%%cmm%d", c, idx);
}


/* Disassemble GPR operands */
static int __disasm_gpr(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn, int idx)
{
	switch (opnd[1]) {
	case 'b':
		return psnprint_gpr8(buf, len, idx);
	case 'w':
		return psnprint_gpr16(buf, len, idx);
	case 'd':
		return psnprint_gpr32(buf, len, idx);
	case 'l':
		if (insn->opnd_bytes == 8)
			return psnprint_gpr64(buf, len, idx);
		else
			return psnprint_gpr32(buf, len, idx);
	case 'v':
	case 'y':
		if (insn->opnd_bytes == 8)
			return psnprint_gpr64(buf, len, idx);
		else if (insn->opnd_bytes == 4)
			return psnprint_gpr32(buf, len, idx);
		else
			return psnprint_gpr16(buf, len, idx);
	default:
		return psnprintf(buf, len, "(%.*s)(bad)", end - opnd, opnd);
	}
}

/* Disassemble GPR operand from RM bits */
static int disasm_rm_gpr(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn)
{
	int idx = X86_MODRM_RM(insn->modrm.bytes[0]);
	if (insn_rex_b_bit(insn))
		idx += 8;
	return __disasm_gpr(buf, len, opnd, end, insn, idx);
}

/* Disassemble GPR operand from Reg bits */
static int disasm_reg_gpr(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn)
{
	int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
	if (insn_rex_r_bit(insn))
		idx += 8;
	else if (insn->rex_prefix.nbytes && opnd[1] == 'b')
		return psnprint_gpr8_rex(buf, len, idx);
	return __disasm_gpr(buf, len, opnd, end, insn, idx);
}

/* Disassemble GPR operand from VEX.v bits */
static int disasm_vex_gpr(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn)
{
	int idx = 15 - insn_vex_v_bits(insn);
	return __disasm_gpr(buf, len, opnd, end, insn, idx);
}

/* Disassemble GPR operand from Opcode */
static int disasm_opcode_gpr(char **buf, size_t *len, const char *opnd,
			     const char *end, struct insn *insn)
{
	int idx = X86_OPCODE_GPR(insn->opcode.bytes[insn->opcode.nbytes - 1]);
	if (insn_rex_b_bit(insn))
		idx += 8;
	return __disasm_gpr(buf, len, opnd, end, insn, idx);
}

/* Disassemble GPR for Effective Address */
static int __disasm_gprea(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn, int idx)
{
	if (insn->addr_bytes == 8)
		return psnprint_gpr64(buf, len, idx);
	else if (insn->addr_bytes == 4)
		return psnprint_gpr32(buf, len, idx);
	else
		return psnprintf(buf, len, "%%%s", gprea16_map[idx]);
}

/* Disassemble a segment prefix */
static int __disasm_segment_prefix(char **buf, size_t *len,
				   struct insn *insn, insn_attr_t def_attr)
{
	insn_attr_t attr = insn_has_segment_prefix(insn);

	if (!attr) {
		if (!def_attr)
			return 0;
		else
			attr = def_attr;
	}

	attr = (attr & INAT_PFX_MASK) - INAT_SEGPFX_MIN;
	return psnprintf(buf, len, "%%%s:", segreg_map[attr]);
}

static int disasm_segment_prefix(char **buf, size_t *len, struct insn *insn)
{
	return __disasm_segment_prefix(buf, len, insn, 0);
}

static int disasm_displacement(char **buf, size_t *len, struct insn *insn)
{
	__disasm_segment_prefix(buf, len, insn, INAT_PFX_DS);
	return psnprintf(buf, len, "0x%x", insn->displacement.value);
}

/* Disassemble SIB byte */
static int disasm_sib(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn)
{
	int mod = X86_MODRM_MOD(insn->modrm.bytes[0]);
	int scale = X86_SIB_SCALE(insn->sib.bytes[0]);
	int index = X86_SIB_INDEX(insn->sib.bytes[0]);
	int base = X86_SIB_BASE(insn->sib.bytes[0]);
	int rexb = insn_rex_b_bit(insn) ? 8 : 0; 
	int rexx = insn_rex_x_bit(insn) ? 8 : 0;

	/* Check the case which has just a displacement */
	if (mod == 0 && index == 4 && base == 5)
		return disasm_displacement(buf, len, insn);

	disasm_segment_prefix(buf, len, insn);
	if (mod != 0 || base == 5) {	/* With displacement offset */
		if (insn->displacement.value < 0)
			psnprintf(buf, len, "-0x%x", -insn->displacement.value);
		else
			psnprintf(buf, len, "0x%x", insn->displacement.value);
	}
	psnprintf(buf, len, "(");
	if (mod != 0 || base != 5)	/* With base */
		__disasm_gprea(buf, len, opnd, end, insn, base + rexb);

	if (index != 4)	{	/* With scale * index */
		psnprintf(buf, len, ",");
		__disasm_gprea(buf, len, opnd, end, insn, index + rexx);
		psnprintf(buf, len, ",%x", 1 << scale);
	}
	return psnprintf(buf, len, ")");
}

/* Disassemble memory-register from MODR/M */
static int disasm_modrm(char **buf, size_t *len, const char *opnd,
			const char *end, struct insn *insn)
{
	int mod = X86_MODRM_MOD(insn->modrm.bytes[0]);
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);

	if (bad_modrm_operand(*opnd, mod))
		psnprintf(buf, len, "(bad)");

	if (mod == 0x3)	{ /* mod == 11B: GPR, MM or XMM */
		if (operand_is_mmx_rm(opnd))
			return psnprintf(buf, len, "%%mm%d", rm);
		else if (operand_is_xmm_rm(opnd)) {
			if (insn_rex_b_bit(insn))
				rm += 8;
			return psnprint_xmmreg(buf, len, opnd, insn, rm);
		} else
			return disasm_rm_gpr(buf, len, opnd, end, insn);
	}

	/* Memory addressing */
	if (insn->sib.nbytes)	/* SIB addressing */
		return disasm_sib(buf, len, opnd, end, insn);

	if (mod == 0 && rm == 5) {	/* displacement only */
		if (insn_rip_relative(insn))	/* RIP relative */
			return psnprintf(buf, len, "0x%x(%rip)",
					  insn->displacement.value);
		else
			return disasm_displacement(buf, len, insn);
	} else {
		disasm_segment_prefix(buf, len, insn);
		if (mod != 0) {
			if (insn->displacement.value < 0)
				psnprintf(buf, len, "-0x%x", -insn->displacement.value);
			else
				psnprintf(buf, len, "0x%x", insn->displacement.value);
		}
		psnprintf(buf, len, "(");
		if (insn_rex_b_bit(insn))
			rm += 8;
		__disasm_gprea(buf, len, opnd, end, insn, rm);
		return psnprintf(buf, len, ")");
	}
}

static int disasm_immediate(char **buf, size_t *len, const char *opnd,
			    const char *end, struct insn *insn)
{
	long long imm;
	int size;

	if (inat_has_moffset(insn->attr) && insn->addr_bytes == 8) {
		/* 64bit memory offset */
		unsigned long long moffs;
		moffs = insn_field_get_uval(&insn->immediate2);
		moffs <<= 32;
		moffs += insn_field_get_uval(&insn->immediate);
		__disasm_segment_prefix(buf, len, insn, INAT_PFX_DS);
		return psnprintf(buf, len, "0x%llx", moffs);
	}

	/* Immediates are sign-extended */
	if (inat_has_second_immediate(insn->attr) &&
	    opnd[0] == 'I' && opnd[1] == 'b')
		imm = insn->immediate2.value;
	else
		imm = insn->immediate1.value;

	if (opnd[0] == 'J' || opnd[0] == 'A') {
		if (opnd[0] == 'J') /* Relative from IP */
			imm += (long)insn->kaddr + insn->length;
		return psnprint_symbol(buf, len, (unsigned long)imm);
	}

	size = insn->opnd_bytes;
	if (opnd[1] == 'B')
		size = 1;
	switch (size) {
	case 8:
		return psnprintf(buf, len, "$0x%llx", imm);
	case 4:
		return psnprintf(buf, len, "$0x%x", (unsigned int)imm);
	case 2:
		return psnprintf(buf, len, "$0x%x", (unsigned short)imm);
	default:
		return psnprintf(buf, len, "$0x%x", (unsigned char)imm);
	}
}

static int disasm_fixmem(char **buf, size_t *len, const char *opnd,
			 const char *end, struct insn *insn)
{
	const char *pfx = "";
	if (insn->addr_bytes == 4)
		pfx = "e";
	else if (insn->addr_bytes == 8)
		pfx = "r";

	return psnprintf(buf, len, "%%%cs:(%%%s%ci)", *opnd == 'X' ? 'd' : 'e',
			 pfx, *opnd == 'X' ? 's' : 'd');
}

static int disasm_register(char **buf, size_t *len, const char *opnd,
			   const char *end, struct insn *insn)
{
	char pfx[2] = {'\0', '\0'};

	if (*opnd == '_') {
		if (opnd[1] == 'r' || opnd[1] == 'e') {
			if (insn->opnd_bytes == 4)
				pfx[0] = 'e';
			else if (insn->opnd_bytes == 8)
				pfx[0] = opnd[1];
			opnd += 2;
			return psnprintf(buf, len, "%%%s%.*s", pfx, end - opnd, opnd);
		} else
			return disasm_opcode_gpr(buf, len, opnd, end, insn);
	} else
		return psnprintf(buf, len, "%%%.*s", end - opnd, opnd);
}

/* Disassembe an operand */
static int disasm_operand(char **buf, size_t *len, const char *opnd,
			  const char *end, struct insn *insn)
{
	if (operand_is_register(opnd))
		return disasm_register(buf, len, opnd, end, insn);
	else if (operand_is_memreg(opnd))	/* Mod and RM */
		return disasm_modrm(buf, len, opnd, end, insn);
	else if (operand_is_imm(opnd)) /* Immedate */
		return disasm_immediate(buf, len, opnd, end, insn);
	else if (operand_is_gp_reg(opnd))
		return disasm_reg_gpr(buf, len, opnd, end, insn);
	else if (operand_is_ctl_reg(opnd)) {
		int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
		return psnprintf(buf, len, "%%cr%d", idx);
	} else if (operand_is_dbg_reg(opnd)) {
		int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
		return psnprintf(buf, len, "%%dr%d", idx);
	} else if (operand_is_seg_reg(opnd)) {
		int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
		return psnprintf(buf, len, "%%%s", segreg_map[idx]);
	} else if (operand_is_mmxreg(opnd)) {
		int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
		return psnprintf(buf, len, "%%mm%d", idx);
	} else if (operand_is_xmmreg(opnd)) {
		int idx = X86_MODRM_REG(insn->modrm.bytes[0]);
		if (insn_rex_r_bit(insn))
			idx += 8;
		return psnprint_xmmreg(buf, len, opnd, insn, idx);
	} else if (operand_is_xmm_vex(opnd)) {
		int idx = 15 - insn_vex_v_bits(insn);
		return psnprint_xmmreg(buf, len, opnd, insn, idx);
	} else if (operand_is_xmm_imm(opnd)) {
		int idx = (insn->immediate.bytes[0] >> 4);
		return psnprint_xmmreg(buf, len, opnd, insn, idx);
	} else if (operand_is_gpr_vex(opnd))
		return disasm_vex_gpr(buf, len, opnd, end, insn);
	else if (operand_is_fixmem(opnd))
		return disasm_fixmem(buf, len, opnd, end, insn);
	else if (operand_is_flags(opnd))
		/* Ignore EFLAGS/RFLAGS */
		return 0;
	else /* Unknown type */
		return psnprintf(buf, len, "(%.*s)", end - opnd, opnd);
}

/**
 * disassemble() - Disassemble given instruction
 * @buf:	A buffer in which assembly code is stored
 * @len:	The size of @buf
 * @insn:	An instruction which will be disassembled
 *
 * This disassembles given instruction.
 * Caller must decode @insn with insn_get_length().
 */
int disassemble(char *buf, size_t len, struct insn *insn)
{
	const char *mn_fmt;
	const char *grp_fmt = NULL;
	const char *prefix;
	const char *p, *q = NULL;
	size_t orig_len = len;
	int ret;

	/* Get the mnemonic format of given instruction */
	mn_fmt = get_mnemonic_format(insn, &grp_fmt);
	if (!mn_fmt)
		return -ENOENT;

	/* Put a prefix if exist */
	prefix = get_prefix_name(insn);
	if (prefix) {
		ret = psnprintf(&buf, &len, "%s ", prefix);
		if (ret < 0)
			return ret;
	}

	/* Get operand */
	q = p = strpbrk(mn_fmt, " |");	/* q is the end of opcode */
	if (grp_fmt) {	/* Group opcode */
		q = strpbrk(grp_fmt, " |");
		mn_fmt = grp_fmt;
		if (!p)	/* No group operand. use individual operand */
			p = q;
	}

	/* Print opcode */
	if (!q)
		ret = psnprintf(&buf, &len, "%-6s ", mn_fmt);
	else
		ret = psnprintf(&buf, &len, "%-6.*s ", q - mn_fmt, mn_fmt);

	/* Disassemble operands */
	while (p && *p != '\0' && *p != '|' && ret >= 0) {
		p++;
		q = strpbrk(p, ",|");
		if (!q)
			q = p + strlen(p);
		ret = disasm_operand(&buf, &len, p, q, insn);
		if (ret < 0)
			break;
		if (*q == ',')
			ret = psnprintf(&buf, &len, ",");
		p = q;
	}

	return ret < 0 ? ret : orig_len - len;
}
