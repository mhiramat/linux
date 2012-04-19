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

/* Print address with symbol if possible (in kernel) */
static int psnprint_symbol(char **buf, size_t *len, unsigned long addr)
{
	int ret;

	ret = psnprintf(buf, len, "%lx", addr);
#ifdef __KERNEL__
	if (ret > 0)
		ret = psnprintf(buf, len, " <%pS>", addr);
#endif
	return ret;
}

typedef int (*disasm_handler_t)(char **buf, size_t *len, const char *opnd,
				struct insn *insn);

/* Operand classifiers */
static bool operand_is_register(const char *p)
{
	return !isupper(*p);
}

static bool operand_is_gpr_reg(const char *p)
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

static bool operand_is_xmm_reg(const char *p)
{
	return *p == 'V';
}

static bool operand_is_mmx_reg(const char *p)
{
	return *p == 'P';
}

/* Operand must be a register */
static bool operand_is_regs_rm(const char *p)
{
	return *p == 'N' || *p == 'U' || *p == 'R';
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
			struct insn *insn, int idx)
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
		return psnprintf(buf, len, "(bad:unkown_%c)", opnd[1]);
	}
}

/* Disassemble register operand from VEX.v bits */
static int disasm_vex_gpr(char **buf, size_t *len, const char *opnd,
			  struct insn *insn)
{
	int idx = 15 - insn_vex_v_bits(insn);
	return __disasm_gpr(buf, len, opnd, insn, idx);
}

static int disasm_vex_xmm(char **buf, size_t *len, const char *opnd,
			  struct insn *insn)
{
	int idx = 15 - insn_vex_v_bits(insn);
	return psnprint_xmmreg(buf, len, opnd, insn, idx);
}

/* Disassemble GPR operand from Opcode */
static int disasm_opcode_gpr(char **buf, size_t *len, const char *opnd,
			     struct insn *insn)
{
	int idx = X86_OPCODE_GPR(insn->opcode.bytes[insn->opcode.nbytes - 1]);
	if (insn_rex_b_bit(insn))
		idx += 8;
	return __disasm_gpr(buf, len, opnd, insn, idx);
}

/* Disassemble GPR for Effective Address */
static int __disasm_gprea(char **buf, size_t *len, const char *opnd,
			  struct insn *insn, int idx)
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
		      struct insn *insn)
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
		__disasm_gprea(buf, len, opnd, insn, base + rexb);

	if (index != 4)	{	/* With scale * index */
		psnprintf(buf, len, ",");
		__disasm_gprea(buf, len, opnd, insn, index + rexx);
		psnprintf(buf, len, ",%x", 1 << scale);
	}
	return psnprintf(buf, len, ")");
}

/* Disassemble memory from MODR/M */
static int disasm_modrm_mem(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	int mod = X86_MODRM_MOD(insn->modrm.bytes[0]);
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);

	if (operand_is_regs_rm(opnd) || mod == 0x3)
		return psnprintf(buf, len, "(bad)");

	/* Memory addressing */
	if (insn->sib.nbytes)	/* SIB addressing */
		return disasm_sib(buf, len, opnd, insn);

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
		__disasm_gprea(buf, len, opnd, insn, rm);
		return psnprintf(buf, len, ")");
	}
}

static int __insn_rm(struct insn *insn)
{
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);
	if (insn_rex_b_bit(insn))
		rm += 8;

	return rm;
}

/* Disassemble memory-register(gpr) from MODR/M */
static int disasm_modrm_gpr(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: GPR */
		return __disasm_gpr(buf, len, opnd, insn, __insn_rm(insn));

	return disasm_modrm_mem(buf, len, opnd, insn);
}

/* Disassemble memory-register(mmx) from MODR/M */
static int disasm_modrm_mmx(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: MMX */
		return psnprintf(buf, len, "%%mm%d", __insn_rm(insn));

	return disasm_modrm_mem(buf, len, opnd, insn);
}

/* Disassemble memory-register(xmm) from MODR/M */
static int disasm_modrm_xmm(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: XMM */
		return psnprint_xmmreg(buf, len, opnd, insn, __insn_rm(insn));

	return disasm_modrm_mem(buf, len, opnd, insn);
}

/* Disassemble immediates */
static int disasm_imm_relip(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	return psnprint_symbol(buf, len, insn->immediate.value + (unsigned long)insn->kaddr + insn->length);
}

static int disasm_imm_absip(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
{
	return psnprint_symbol(buf, len, insn->immediate.value);
}

static int disasm_imm_xmm(char **buf, size_t *len, const char *opnd,
			  struct insn *insn)
{
	int idx = (insn->immediate.bytes[0] >> 4);
	return psnprint_xmmreg(buf, len, opnd, insn, idx);
}

static int disasm_immediate(char **buf, size_t *len, const char *opnd,
			    struct insn *insn)
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

	size = insn->opnd_bytes;
	if (opnd[1] == 'B')	/* Forcibly 8bit cast */
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
			 struct insn *insn)
{
	const char *pfx = "";
	if (insn->addr_bytes == 4)
		pfx = "e";
	else if (insn->addr_bytes == 8)
		pfx = "r";

	return psnprintf(buf, len, "%%%cs:(%%%s%ci)", *opnd == 'X' ? 'd' : 'e',
			 pfx, *opnd == 'X' ? 's' : 'd');
}

/* Disassemble any register operand from Reg bits */
static int disasm_reg_regs(char **buf, size_t *len, const char *opnd,
			   struct insn *insn)
{
	int idx = X86_MODRM_REG(insn->modrm.bytes[0]);

	if (insn_rex_r_bit(insn))
		idx += 8;

	if (operand_is_gpr_reg(opnd)) {
		if (insn->rex_prefix.nbytes && opnd[1] == 'b')
			return psnprint_gpr8_rex(buf, len, idx);
		else
			return __disasm_gpr(buf, len, opnd, insn, idx);
	}

	if (operand_is_xmm_reg(opnd))
		return psnprint_xmmreg(buf, len, opnd, insn, idx);

	if (idx > 7 && !(operand_is_dbg_reg(opnd) && idx == 8))
		goto err;

	if (operand_is_ctl_reg(opnd))
		return psnprintf(buf, len, "%%cr%d", idx);
	else if (operand_is_dbg_reg(opnd))
		return psnprintf(buf, len, "%%dr%d", idx);
	else if (operand_is_seg_reg(opnd))
		return psnprintf(buf, len, "%%%s", segreg_map[idx]);
	else if (operand_is_mmx_reg(opnd))
		return psnprintf(buf, len, "%%mm%d", idx);

err:
	return psnprintf(buf, len, "(bad)");
}

static int disasm_flags(char **buf, size_t *len, const char *opnd,
			struct insn *insn)
{
	/* Ignore EFLAGS/RFLAGS */
	return 0;
}

/* Operand code of addressing methods - see Intel SDM A.2.1 */
#define opnd2idx(abbr)	(abbr - 'A')
#define DEFINE_ADDR_METHOD(abbr, method) [opnd2idx(abbr)] = method
#define MAX_ADDR_METHODS	26

static const disasm_handler_t addressing_methods[MAX_ADDR_METHODS] = {
	DEFINE_ADDR_METHOD('A', disasm_imm_absip),
	DEFINE_ADDR_METHOD('B', disasm_vex_gpr),
	DEFINE_ADDR_METHOD('C', disasm_reg_regs),
	DEFINE_ADDR_METHOD('D', disasm_reg_regs),
	DEFINE_ADDR_METHOD('E', disasm_modrm_gpr),
	DEFINE_ADDR_METHOD('F', disasm_flags),
	DEFINE_ADDR_METHOD('G', disasm_reg_regs),
	DEFINE_ADDR_METHOD('H', disasm_vex_xmm),
	DEFINE_ADDR_METHOD('I', disasm_immediate),
	DEFINE_ADDR_METHOD('J', disasm_imm_relip),
	DEFINE_ADDR_METHOD('K', NULL),
	DEFINE_ADDR_METHOD('L', disasm_imm_xmm),
	DEFINE_ADDR_METHOD('M', disasm_modrm_mem),
	DEFINE_ADDR_METHOD('N', disasm_modrm_mmx),
	DEFINE_ADDR_METHOD('O', disasm_immediate),
	DEFINE_ADDR_METHOD('P', disasm_reg_regs),
	DEFINE_ADDR_METHOD('Q', disasm_modrm_mmx),
	DEFINE_ADDR_METHOD('R', disasm_modrm_gpr),
	DEFINE_ADDR_METHOD('S', disasm_reg_regs),
	DEFINE_ADDR_METHOD('T', NULL),
	DEFINE_ADDR_METHOD('U', disasm_modrm_xmm),
	DEFINE_ADDR_METHOD('V', disasm_reg_regs),
	DEFINE_ADDR_METHOD('W', disasm_modrm_xmm),
	DEFINE_ADDR_METHOD('X', disasm_fixmem),
	DEFINE_ADDR_METHOD('Y', disasm_fixmem),
	DEFINE_ADDR_METHOD('Z', NULL),
};

static disasm_handler_t get_addressing_method(const char *opnd)
{
	int idx = opnd2idx(opnd[0]);

	if (idx < 0 || idx >= MAX_ADDR_METHODS)
		return NULL;

	return addressing_methods[idx];
}

/* Disassemble raw register operand */
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
			return disasm_opcode_gpr(buf, len, opnd, insn);
	} else
		return psnprintf(buf, len, "%%%.*s", end - opnd, opnd);
}

/* Disassembe an operand */
static int disasm_operand(char **buf, size_t *len, const char *opnd,
			  const char *end, struct insn *insn)
{
	disasm_handler_t disasm_op;

	if (operand_is_register(opnd))
		return disasm_register(buf, len, opnd, end, insn);

	disasm_op = get_addressing_method(opnd);
	if (!disasm_op)	/* Unknown type */
		return psnprintf(buf, len, "(bad:%.*s)", end - opnd, opnd);

	return disasm_op(buf, len, opnd, insn);
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
