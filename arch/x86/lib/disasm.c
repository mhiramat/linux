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

struct disasm_buffer{
	char	*buf;
	size_t	len;
	int	syntax;
};

static bool disasm_syntax_intel(struct disasm_buffer *dbuf)
{
	return dbuf->syntax == DISASM_SYNTAX_INTEL;
}

static int disasm_vprintf(struct disasm_buffer *dbuf, const char *fmt, va_list ap)
{
	int ret;

	ret = vsnprintf(dbuf->buf, dbuf->len, fmt, ap);
	if (ret > 0 && ret < dbuf->len) {
		dbuf->buf += ret;
		dbuf->len -= ret;
	} else
		ret = -E2BIG;

	return ret;
}

static int disasm_printf(struct disasm_buffer *dbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = disasm_vprintf(dbuf, fmt, ap);
	va_end(ap);

	return ret;
}

/* Print address with symbol if possible (in kernel) */
static int disasm_printsym(struct disasm_buffer *dbuf, unsigned long addr)
{
	int ret;

	ret = disasm_printf(dbuf, "%lx", addr);
#ifdef __KERNEL__
	if (ret > 0)
		ret = disasm_printf(dbuf, " <%pS>", addr);
#endif
	return ret;
}

static int disasm_printreg(struct disasm_buffer *dbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	if (dbuf->syntax == DISASM_SYNTAX_ATT) {
		if (dbuf->len <= 1)
			return -E2BIG;
		dbuf->buf[0] = '%';
		dbuf->len--;
		dbuf->buf++;
	}
	va_start(ap, fmt);
	ret = disasm_vprintf(dbuf, fmt, ap);
	va_end(ap);

	return ret;
}

typedef int (*disasm_handler_t)(struct disasm_buffer *dbuf, const char *opnd,
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
static int psnprint_gpr8(struct disasm_buffer *dbuf, int idx)
{
	if (idx < 8)
		return disasm_printreg(dbuf, "%s", gpreg8_map[idx]);
	else
		return disasm_printreg(dbuf, "r%db", idx);
}

/* Special exception for reg bits encoding with rex prefix */
static int psnprint_gpr8_rex(struct disasm_buffer *dbuf, int idx)
{
	if (idx < 8)
		return disasm_printreg(dbuf, "%s", gpreg8_map2[idx]);
	else
		return disasm_printreg(dbuf, "r%db", idx);
}

static int psnprint_gpr16(struct disasm_buffer *dbuf, int idx)
{
	if (idx < 8)
		return disasm_printreg(dbuf, "%s", gpreg_map[idx]);
	else
		return disasm_printreg(dbuf, "r%dw", idx);
}

static int psnprint_gpr32(struct disasm_buffer *dbuf, int idx)
{
	if (idx < 8)
		return disasm_printreg(dbuf, "e%s", gpreg_map[idx]);
	else
		return disasm_printreg(dbuf, "r%dd", idx);
}

static int psnprint_gpr64(struct disasm_buffer *dbuf, int idx)
{
	if (idx < 8)
		return disasm_printreg(dbuf, "r%s", gpreg_map[idx]);
	else
		return disasm_printreg(dbuf, "r%d", idx);
}

static int psnprint_xmmreg(struct disasm_buffer *dbuf, const char *opnd,
			   struct insn *insn, int idx)
{
	int c = 'x';
	if (opnd[1] == 'q' ||	/* Should be Quad-Quad(qq)word */
	    (opnd[1] != 's' && insn_vex_l_bit(insn)))
		c = 'y';

	return disasm_printreg(dbuf, "%cmm%d", c, idx);
}

/* Disassemble GPR operands */
static int __disasm_gpr(struct disasm_buffer *dbuf, const char *opnd,
			struct insn *insn, int idx)
{
	switch (opnd[1]) {
	case 'b':
		return psnprint_gpr8(dbuf, idx);
	case 'w':
		return psnprint_gpr16(dbuf, idx);
	case 'l':
		if (insn->opnd_bytes == 8)
			return psnprint_gpr64(dbuf, idx);
		else
			return psnprint_gpr32(dbuf, idx);
	case 'v':
	case 'y':
		if (insn->opnd_bytes == 8)
			return psnprint_gpr64(dbuf, idx);
		else if (insn->opnd_bytes == 4)
			return psnprint_gpr32(dbuf, idx);
		else
			return psnprint_gpr16(dbuf, idx);
	default:
		return disasm_printf(dbuf, "(bad:unkown_%c)", opnd[1]);
	}
}

/* Disassemble register operand from VEX.v bits */
static int disasm_vex_gpr(struct disasm_buffer *dbuf, const char *opnd,
			  struct insn *insn)
{
	int idx = 15 - insn_vex_v_bits(insn);
	return __disasm_gpr(dbuf, opnd, insn, idx);
}

static int disasm_vex_xmm(struct disasm_buffer *dbuf, const char *opnd,
			  struct insn *insn)
{
	int idx = 15 - insn_vex_v_bits(insn);
	return psnprint_xmmreg(dbuf, opnd, insn, idx);
}

/* Disassemble GPR operand from Opcode */
static int disasm_opcode_gpr(struct disasm_buffer *dbuf, const char *opnd,
			     struct insn *insn)
{
	int idx = X86_OPCODE_GPR(insn->opcode.bytes[insn->opcode.nbytes - 1]);
	if (insn_rex_r_bit(insn))
		idx += 8;
	return __disasm_gpr(dbuf, opnd, insn, idx);
}

/* Disassemble GPR for Effective Address */
static int __disasm_gprea(struct disasm_buffer *dbuf, struct insn *insn, int idx)
{
	if (insn->addr_bytes == 8)
		return psnprint_gpr64(dbuf, idx);
	else if (insn->addr_bytes == 4)
		return psnprint_gpr32(dbuf, idx);
	else
		return disasm_printreg(dbuf, "%s", gprea16_map[idx]);
}

static int get_operand_size(struct insn *insn, int type)
{
	int size = insn->opnd_bytes;

	switch (type) {
	case 'b':
	case 'B':
		size = 1;
		break;
	case 'w':
		size = 2;
		break;
	case 'd':
		size = 4;
		break;
	case 'q':
		size = 8;
		break;
	case 'z':
		if (size == 8)
			size = 4;
		break;
	}
	return size;
}

static int disasm_pointer_prefix(struct disasm_buffer *dbuf, const char *opnd,
				 struct insn *insn)
{
	const char *type = "(bad)";

	switch (get_operand_size(insn, opnd[1])) {
	case 1:
		type = "BYTE";
		break;
	case 2:
		type = "WORD";
		break;
	case 4:
		type = "DWORD";
		break;
	case 8:
		type = "QWORD";
		break;
	}
	return disasm_printf(dbuf, "%s PTR ", type);
}

/* Disassemble a segment prefix */
static int __disasm_segment_prefix(struct disasm_buffer *dbuf,
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
	return disasm_printreg(dbuf, "%s:", segreg_map[attr]);
}

static int disasm_segment_prefix(struct disasm_buffer *dbuf, struct insn *insn)
{
	return __disasm_segment_prefix(dbuf, insn, 0);
}

static int disasm_displacement(struct disasm_buffer *dbuf, struct insn *insn)
{
	__disasm_segment_prefix(dbuf, insn, INAT_PFX_DS);
	return disasm_printf(dbuf, "0x%x", insn->displacement.value);
}

static int disasm_rip_relative(struct disasm_buffer *dbuf, struct insn *insn)
{
	if (disasm_syntax_intel(dbuf))
		return disasm_printf(dbuf, "[rip+0x%x]",
				     insn->displacement.value);
	else
		return disasm_printf(dbuf, "0x%x(%rip)",
				     insn->displacement.value);
}

static int disasm_sib_intel(struct disasm_buffer *dbuf, struct insn *insn,
	int mod, int scale, int index, int base, int disp, int rexb, int rexx)
{
	disasm_printf(dbuf, "[");
	if (mod != 0 || base != 5)	/* With base */
		__disasm_gprea(dbuf, insn, base + rexb);

	if (index != 4)	{	/* With scale * index */
		if (mod != 0 || base != 5)	/* With base */
			disasm_printf(dbuf, "+");
		__disasm_gprea(dbuf, insn, index + rexx);
		disasm_printf(dbuf, "*%x", 1 << scale);
	}

	if (mod != 0 || base == 5) {	/* With displacement offset */
		if (disp < 0)
			disasm_printf(dbuf, "-0x%x", -disp);
		else
			disasm_printf(dbuf, "+0x%x", disp);
	}
	return disasm_printf(dbuf, "]");
}

/* Disassemble SIB byte */
static int disasm_sib(struct disasm_buffer *dbuf, struct insn *insn, int mod)
{
	int scale = X86_SIB_SCALE(insn->sib.bytes[0]);
	int index = X86_SIB_INDEX(insn->sib.bytes[0]);
	int base = X86_SIB_BASE(insn->sib.bytes[0]);
	int rexb = insn_rex_b_bit(insn) ? 8 : 0; 
	int rexx = insn_rex_x_bit(insn) ? 8 : 0;

	/* Check the case which has just a displacement */
	if (mod == 0 && index == 4 && base == 5)
		return disasm_displacement(dbuf, insn);

	disasm_segment_prefix(dbuf, insn);
	if (disasm_syntax_intel(dbuf))
		return disasm_sib_intel(dbuf, insn, mod, scale, index, base,
					insn->displacement.value, rexb, rexx);

	if (mod != 0 || base == 5) {	/* With displacement offset */
		if (insn->displacement.value < 0)
			disasm_printf(dbuf, "-0x%x", -insn->displacement.value);
		else
			disasm_printf(dbuf, "0x%x", insn->displacement.value);
	}
	disasm_printf(dbuf, "(");
	if (mod != 0 || base != 5)	/* With base */
		__disasm_gprea(dbuf, insn, base + rexb);

	if (index != 4)	{	/* With scale * index */
		disasm_printf(dbuf, ",");
		__disasm_gprea(dbuf, insn, index + rexx);
		disasm_printf(dbuf, ",%x", 1 << scale);
	}
	return disasm_printf(dbuf, ")");
}

static int disasm_modrm_ea(struct disasm_buffer *dbuf, struct insn *insn,
			   int mod, int rm, long disp)
{
	disasm_segment_prefix(dbuf, insn);

	if (disasm_syntax_intel(dbuf)) {
		disasm_printf(dbuf, "[");
		__disasm_gprea(dbuf, insn, rm);
		if (mod != 0) {
			if (disp < 0)
				disasm_printf(dbuf, "-0x%x", -disp);
			else
				disasm_printf(dbuf, "+0x%x", disp);
		}
		return disasm_printf(dbuf, "]");
	} else {
		if (mod != 0) {
			if (disp < 0)
				disasm_printf(dbuf, "-0x%x", -disp);
			else
				disasm_printf(dbuf, "0x%x", disp);
		}
		disasm_printf(dbuf, "(");
		__disasm_gprea(dbuf, insn, rm);
		return disasm_printf(dbuf, ")");
	}
}

/* Disassemble memory from MODR/M */
static int disasm_modrm_mem(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	int mod = X86_MODRM_MOD(insn->modrm.bytes[0]);
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);

	if (operand_is_regs_rm(opnd) || mod == 0x3)
		return disasm_printf(dbuf, "(bad)");

	/* Memory addressing */
	if (disasm_syntax_intel(dbuf))
		/* Since LEA doesn't use operand as a pointer, skip it */
		if (insn->opcode.bytes[0] != X86_LEA_OPCODE)
			disasm_pointer_prefix(dbuf, opnd, insn);

	if (insn->sib.nbytes)	/* SIB addressing */
		return disasm_sib(dbuf, insn, mod);

	if (mod == 0 && rm == 5) {	/* displacement only */
		if (insn_rip_relative(insn))	/* RIP relative */
			return disasm_rip_relative(dbuf, insn);
		else
			return disasm_displacement(dbuf, insn);
	}

	if (insn_rex_b_bit(insn))
		rm += 8;
	return disasm_modrm_ea(dbuf, insn, mod, rm, insn->displacement.value);
}

static int __insn_rm(struct insn *insn)
{
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);
	if (insn_rex_b_bit(insn))
		rm += 8;

	return rm;
}

/* Disassemble memory-register(gpr) from MODR/M */
static int disasm_modrm_gpr(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: GPR */
		return __disasm_gpr(dbuf, opnd, insn, __insn_rm(insn));

	return disasm_modrm_mem(dbuf, opnd, insn);
}

/* Disassemble memory-register(mmx) from MODR/M */
static int disasm_modrm_mmx(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: MMX */
		return disasm_printreg(dbuf, "mm%d", __insn_rm(insn));

	return disasm_modrm_mem(dbuf, opnd, insn);
}

/* Disassemble memory-register(xmm) from MODR/M */
static int disasm_modrm_xmm(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	if (X86_MODRM_MOD(insn->modrm.bytes[0]) == 0x3)	/* mod == 11B: XMM */
		return psnprint_xmmreg(dbuf, opnd, insn, __insn_rm(insn));

	return disasm_modrm_mem(dbuf, opnd, insn);
}

/* Disassemble immediates */
static int disasm_imm_relip(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	return disasm_printsym(dbuf, insn->immediate.value + (unsigned long)insn->kaddr + insn->length);
}

static int disasm_imm_absip(struct disasm_buffer *dbuf, const char *opnd,
			    struct insn *insn)
{
	return disasm_printsym(dbuf, insn->immediate.value);
}

static int disasm_imm_xmm(struct disasm_buffer *dbuf, const char *opnd,
			  struct insn *insn)
{
	int idx = (insn->immediate.bytes[0] >> 4);
	return psnprint_xmmreg(dbuf, opnd, insn, idx);
}

static int disasm_immediate(struct disasm_buffer *dbuf, const char *opnd,
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
		__disasm_segment_prefix(dbuf, insn, INAT_PFX_DS);
		return disasm_printf(dbuf, "0x%llx", moffs);
	}

	/* Immediates are sign-extended */
	if (inat_has_second_immediate(insn->attr) &&
	    opnd[0] == 'I' && opnd[1] == 'b')
		imm = insn->immediate2.value;
	else
		imm = insn->immediate1.value;

	if (!disasm_syntax_intel(dbuf))
		disasm_printf(dbuf, "$");

	size = insn->opnd_bytes;
	if (opnd[1] == 'B')	/* Forcibly 8bit cast */
		size = 1;
	switch (size) {
	case 8:
		return disasm_printf(dbuf, "0x%llx", imm);
	case 4:
		return disasm_printf(dbuf, "0x%x", (unsigned int)imm);
	case 2:
		return disasm_printf(dbuf, "0x%x", (unsigned short)imm);
	default:
		return disasm_printf(dbuf, "0x%x", (unsigned char)imm);
	}
}

static int disasm_fixmem(struct disasm_buffer *dbuf, const char *opnd,
			 struct insn *insn)
{
	const char *pfx = "";
	int ret;

	if (insn->addr_bytes == 4)
		pfx = "e";
	else if (insn->addr_bytes == 8)
		pfx = "r";

	ret = disasm_printreg(dbuf, "%cs:(", *opnd == 'X' ? 'd' : 'e');
	if (ret < 0)
		return ret;
	return disasm_printreg(dbuf, "%s%ci)", pfx, *opnd == 'X' ? 's' : 'd');
}

/* Disassemble any register operand from Reg bits */
static int disasm_reg_regs(struct disasm_buffer *dbuf, const char *opnd,
			   struct insn *insn)
{
	int idx = X86_MODRM_REG(insn->modrm.bytes[0]);

	if (insn_rex_r_bit(insn))
		idx += 8;

	if (operand_is_gpr_reg(opnd)) {
		if (insn->rex_prefix.nbytes && opnd[1] == 'b')
			return psnprint_gpr8_rex(dbuf, idx);
		else
			return __disasm_gpr(dbuf, opnd, insn, idx);
	}

	if (operand_is_xmm_reg(opnd))
		return psnprint_xmmreg(dbuf, opnd, insn, idx);

	if (idx > 7 && !(operand_is_dbg_reg(opnd) && idx == 8))
		goto err;

	if (operand_is_ctl_reg(opnd))
		return disasm_printreg(dbuf, "cr%d", idx);
	else if (operand_is_dbg_reg(opnd))
		return disasm_printreg(dbuf, "dr%d", idx);
	else if (operand_is_seg_reg(opnd))
		return disasm_printreg(dbuf, "%s", segreg_map[idx]);
	else if (operand_is_mmx_reg(opnd))
		return disasm_printreg(dbuf, "mm%d", idx);

err:
	return disasm_printf(dbuf, "(bad register)");
}

static int disasm_flags(struct disasm_buffer *dbuf, const char *opnd,
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
static int disasm_register(struct disasm_buffer *dbuf, const char *opnd,
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
			return disasm_printreg(dbuf, "%s%.*s", pfx, end - opnd, opnd);
		} else
			return disasm_opcode_gpr(dbuf, opnd, insn);
	} else
		return disasm_printreg(dbuf, "%.*s", end - opnd, opnd);
}

/* Disassembe an operand */
static int disasm_operand(struct disasm_buffer *dbuf, const char *opnd,
			  const char *end, struct insn *insn)
{
	disasm_handler_t disasm_op;

	if (operand_is_register(opnd))
		return disasm_register(dbuf, opnd, end, insn);

	disasm_op = get_addressing_method(opnd);
	if (!disasm_op)	/* Unknown type */
		return disasm_printf(dbuf, "(bad:%.*s)", end - opnd, opnd);

	return disasm_op(dbuf, opnd, insn);
}

/* Start disassembling from the end of operands */
static int disasm_operands_intel(struct disasm_buffer *dbuf, const char *s_opr,
				 struct insn *insn)
{
	const char *e;
	int ret;

	while (*s_opr != '\0' && *s_opr != '|')
		s_opr++;

	do {
		e = s_opr--;
		while (*s_opr != ',' && *s_opr != ' ')
			s_opr--;
		ret = disasm_operand(dbuf, s_opr + 1, e, insn);
		if (ret < 0 || *s_opr == ' ')
			break;
		ret = disasm_printf(dbuf, ",");
	} while (ret >= 0);

	return ret;
}

/* Start disassembling from the head of operands */
static int disasm_operands_att(struct disasm_buffer *dbuf, const char *s_opr,
			       struct insn *insn)
{
	const char *e;
	int ret;

	while (*s_opr != '\0' && *s_opr != '|' && ret >= 0) {
		e = ++s_opr;
		while (*e != ',' && *e != '|' && *e != '\0')
			e++;
		ret = disasm_operand(dbuf, s_opr, e, insn);
		if (ret < 0 || *e != ',')
			break;
		ret = disasm_printf(dbuf, ",");
		s_opr = e;
	}
	return ret;
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
int disassemble(char *buf, size_t len, struct insn *insn, int syntax)
{
	struct disasm_buffer dbuf = {.buf = buf, .len = len, .syntax = syntax};
	const char *mn_fmt;
	const char *grp_fmt = NULL;
	const char *prefix;
	const char *p, *q = NULL;
	int ret;

	/* Get the mnemonic format of given instruction */
	mn_fmt = get_mnemonic_format(insn, &grp_fmt);
	if (!mn_fmt)
		return -ENOENT;

	/* Put a prefix if exist */
	prefix = get_prefix_name(insn);
	if (prefix) {
		ret = disasm_printf(&dbuf, "%s ", prefix);
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
		ret = disasm_printf(&dbuf, "%-6s ", mn_fmt);
	else
		ret = disasm_printf(&dbuf, "%-6.*s ", q - mn_fmt, mn_fmt);

	/* Disassemble operands */
	if (!p || *p != ' ')
		goto end;	/* No operand */

	if (disasm_syntax_intel(&dbuf))
		ret = disasm_operands_intel(&dbuf, p, insn);
	else
		ret = disasm_operands_att(&dbuf, p, insn);
end:
	return ret < 0 ? ret : len - dbuf.len;
}
