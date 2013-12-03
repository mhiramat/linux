/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/bpf_jit.h>

static const char *const bpf_class_string[] = {
	"ld", "ldx", "st", "stx", "alu", "jmp", "ret", "misc"
};

static const char *const bpf_alu_string[] = {
	"+=", "-=", "*=", "/=", "|=", "&=", "<<=", ">>=", "neg",
	"%=", "^=", "=", "s>>=", "bswap32", "bswap64", "BUG"
};

static const char *const bpf_ldst_string[] = {
	"u32", "u16", "u8", "u64"
};

static const char *const bpf_jmp_string[] = {
	"jmp", "==", ">", ">=", "&", "!=", "s>", "s>=", "call"
};

static const char *reg_to_str(int regno, u64 *regs)
{
	static char reg_value[16][32];
	if (!regs)
		return "";
	snprintf(reg_value[regno], sizeof(reg_value[regno]), "(0x%llx)",
		 regs[regno]);
	return reg_value[regno];
}

#define R(regno) reg_to_str(regno, regs)

void pr_info_bpf_insn(struct bpf_insn *insn, u64 *regs)
{
	u16 class = BPF_CLASS(insn->code);
	if (class == BPF_ALU) {
		if (BPF_SRC(insn->code) == BPF_X)
			pr_info("code_%02x r%d%s %s r%d%s\n",
				insn->code, insn->a_reg, R(insn->a_reg),
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				insn->x_reg, R(insn->x_reg));
		else
			pr_info("code_%02x r%d%s %s %d\n",
				insn->code, insn->a_reg, R(insn->a_reg),
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				insn->imm);
	} else if (class == BPF_STX) {
		if (BPF_MODE(insn->code) == BPF_REL)
			pr_info("code_%02x *(%s *)(r%d%s %+d) = r%d%s\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->a_reg, R(insn->a_reg),
				insn->off, insn->x_reg, R(insn->x_reg));
		else if (BPF_MODE(insn->code) == BPF_XADD)
			pr_info("code_%02x lock *(%s *)(r%d%s %+d) += r%d%s\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->a_reg, R(insn->a_reg), insn->off,
				insn->x_reg, R(insn->x_reg));
		else
			pr_info("BUG_%02x\n", insn->code);
	} else if (class == BPF_ST) {
		if (BPF_MODE(insn->code) != BPF_REL) {
			pr_info("BUG_st_%02x\n", insn->code);
			return;
		}
		pr_info("code_%02x *(%s *)(r%d%s %+d) = %d\n",
			insn->code,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->a_reg, R(insn->a_reg),
			insn->off, insn->imm);
	} else if (class == BPF_LDX) {
		if (BPF_MODE(insn->code) != BPF_REL) {
			pr_info("BUG_ldx_%02x\n", insn->code);
			return;
		}
		pr_info("code_%02x r%d = *(%s *)(r%d%s %+d)\n",
			insn->code, insn->a_reg,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->x_reg, R(insn->x_reg), insn->off);
	} else if (class == BPF_JMP) {
		u16 opcode = BPF_OP(insn->code);
		if (opcode == BPF_CALL) {
			pr_info("code_%02x call %d\n", insn->code, insn->imm);
		} else if (insn->code == (BPF_JMP | BPF_JA | BPF_X)) {
			pr_info("code_%02x goto pc%+d\n",
				insn->code, insn->off);
		} else if (BPF_SRC(insn->code) == BPF_X) {
			pr_info("code_%02x if r%d%s %s r%d%s goto pc%+d\n",
				insn->code, insn->a_reg, R(insn->a_reg),
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->x_reg, R(insn->x_reg), insn->off);
		} else {
			pr_info("code_%02x if r%d%s %s 0x%x goto pc%+d\n",
				insn->code, insn->a_reg, R(insn->a_reg),
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->imm, insn->off);
		}
	} else {
		pr_info("code_%02x %s\n", insn->code, bpf_class_string[class]);
	}
}

void bpf_run(struct bpf_program *prog, struct bpf_context *ctx)
{
	struct bpf_insn *insn = prog->insns;
	u64 stack[64];
	u64 regs[16] = { };
	regs[__fp__] = (u64)(ulong)&stack[64];
	regs[R1] = (u64)(ulong)ctx;

	for (;; insn++) {
		const s32 K = insn->imm;
		u64 tmp;
		u64 *a_reg = &regs[insn->a_reg];
		u64 *x_reg = &regs[insn->x_reg];
#define A (*a_reg)
#define X (*x_reg)
		/*pr_info_bpf_insn(insn, regs);*/
		switch (insn->code) {
			/* ALU */
		case BPF_ALU | BPF_ADD | BPF_X:
			A += X;
			continue;
		case BPF_ALU | BPF_ADD | BPF_K:
			A += K;
			continue;
		case BPF_ALU | BPF_SUB | BPF_X:
			A -= X;
			continue;
		case BPF_ALU | BPF_SUB | BPF_K:
			A -= K;
			continue;
		case BPF_ALU | BPF_AND | BPF_X:
			A &= X;
			continue;
		case BPF_ALU | BPF_AND | BPF_K:
			A &= K;
			continue;
		case BPF_ALU | BPF_OR | BPF_X:
			A |= X;
			continue;
		case BPF_ALU | BPF_OR | BPF_K:
			A |= K;
			continue;
		case BPF_ALU | BPF_LSH | BPF_X:
			A <<= X;
			continue;
		case BPF_ALU | BPF_LSH | BPF_K:
			A <<= K;
			continue;
		case BPF_ALU | BPF_RSH | BPF_X:
			A >>= X;
			continue;
		case BPF_ALU | BPF_RSH | BPF_K:
			A >>= K;
			continue;
		case BPF_ALU | BPF_MOV | BPF_X:
			A = X;
			continue;
		case BPF_ALU | BPF_MOV | BPF_K:
			A = K;
			continue;
		case BPF_ALU | BPF_ARSH | BPF_X:
			(*(s64 *) &A) >>= X;
			continue;
		case BPF_ALU | BPF_ARSH | BPF_K:
			(*(s64 *) &A) >>= K;
			continue;
		case BPF_ALU | BPF_BSWAP32 | BPF_X:
			A = __builtin_bswap32(A);
			continue;
		case BPF_ALU | BPF_BSWAP64 | BPF_X:
			A = __builtin_bswap64(A);
			continue;
		case BPF_ALU | BPF_MOD | BPF_X:
			tmp = A;
			if (X)
				A = do_div(tmp, X);
			continue;
		case BPF_ALU | BPF_MOD | BPF_K:
			tmp = A;
			if (K)
				A = do_div(tmp, K);
			continue;

			/* CALL */
		case BPF_JMP | BPF_CALL:
			prog->cb->execute_func(prog->strtab, K, regs);
			continue;

			/* JMP */
		case BPF_JMP | BPF_JA | BPF_X:
			insn += insn->off;
			continue;
		case BPF_JMP | BPF_JEQ | BPF_X:
			if (A == X)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JEQ | BPF_K:
			if (A == K)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JNE | BPF_X:
			if (A != X)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JNE | BPF_K:
			if (A != K)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JGT | BPF_X:
			if (A > X)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JGT | BPF_K:
			if (A > K)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JGE | BPF_X:
			if (A >= X)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JGE | BPF_K:
			if (A >= K)
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JSGT | BPF_X:
			if (((s64)A) > ((s64)X))
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JSGT | BPF_K:
			if (((s64)A) > ((s64)K))
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JSGE | BPF_X:
			if (((s64)A) >= ((s64)X))
				insn += insn->off;
			continue;
		case BPF_JMP | BPF_JSGE | BPF_K:
			if (((s64)A) >= ((s64)K))
				insn += insn->off;
			continue;

			/* STX */
		case BPF_STX | BPF_REL | BPF_B:
			*(u8 *)(ulong)(A + insn->off) = X;
			continue;
		case BPF_STX | BPF_REL | BPF_H:
			*(u16 *)(ulong)(A + insn->off) = X;
			continue;
		case BPF_STX | BPF_REL | BPF_W:
			*(u32 *)(ulong)(A + insn->off) = X;
			continue;
		case BPF_STX | BPF_REL | BPF_DW:
			*(u64 *)(ulong)(A + insn->off) = X;
			continue;

			/* ST */
		case BPF_ST | BPF_REL | BPF_B:
			*(u8 *)(ulong)(A + insn->off) = K;
			continue;
		case BPF_ST | BPF_REL | BPF_H:
			*(u16 *)(ulong)(A + insn->off) = K;
			continue;
		case BPF_ST | BPF_REL | BPF_W:
			*(u32 *)(ulong)(A + insn->off) = K;
			continue;
		case BPF_ST | BPF_REL | BPF_DW:
			*(u64 *)(ulong)(A + insn->off) = K;
			continue;

			/* LDX */
		case BPF_LDX | BPF_REL | BPF_B:
			A = *(u8 *)(ulong)(X + insn->off);
			continue;
		case BPF_LDX | BPF_REL | BPF_H:
			A = *(u16 *)(ulong)(X + insn->off);
			continue;
		case BPF_LDX | BPF_REL | BPF_W:
			A = *(u32 *)(ulong)(X + insn->off);
			continue;
		case BPF_LDX | BPF_REL | BPF_DW:
			A = *(u64 *)(ulong)(X + insn->off);
			continue;

			/* STX XADD */
		case BPF_STX | BPF_XADD | BPF_B:
			__sync_fetch_and_add((u8 *)(ulong)(A + insn->off),
					     (u8)X);
			continue;
		case BPF_STX | BPF_XADD | BPF_H:
			__sync_fetch_and_add((u16 *)(ulong)(A + insn->off),
					     (u16)X);
			continue;
		case BPF_STX | BPF_XADD | BPF_W:
			__sync_fetch_and_add((u32 *)(ulong)(A + insn->off),
					     (u32)X);
			continue;
		case BPF_STX | BPF_XADD | BPF_DW:
			__sync_fetch_and_add((u64 *)(ulong)(A + insn->off),
					     (u64)X);
			continue;

			/* RET */
		case BPF_RET | BPF_K:
			return;
		default:
			/*
			 * bpf_check() will guarantee that
			 * we never reach here
			 */
			pr_err("unknown opcode %02x\n", insn->code);
			return;
		}
	}
}
EXPORT_SYMBOL(bpf_run);

/*
 * BPF image format:
 * 4 bytes "bpf\0"
 * 4 bytes - size of insn section in bytes
 * 4 bytes - size of table definition section in bytes
 * 4 bytes - size of strtab section in bytes
 * bpf insns: one or more of 'struct bpf_insn'
 * hash table definitions: zero or more of 'struct bpf_table'
 * string table: zero separated ascii strings
 */
#define BPF_HEADER_SIZE 16
int bpf_load_image(const char *image, int image_len, struct bpf_callbacks *cb,
		   struct bpf_program **p_prog)
{
	struct bpf_program *prog;
	int insn_size, htab_size, strtab_size;
	int ret;

	BUILD_BUG_ON(sizeof(struct bpf_insn) != 8);

	if (!image || !cb || !cb->execute_func || !cb->get_func_proto ||
	    !cb->get_context_access)
		return -EINVAL;

	if (image_len < BPF_HEADER_SIZE + sizeof(struct bpf_insn) ||
	    memcmp(image, "bpf", 4) != 0) {
		pr_err("invalid bpf image, size=%d\n", image_len);
		return -EINVAL;
	}

	memcpy(&insn_size, image + 4, 4);
	memcpy(&htab_size, image + 8, 4);
	memcpy(&strtab_size, image + 12, 4);

	if (insn_size % sizeof(struct bpf_insn) ||
	    htab_size % sizeof(struct bpf_table) ||
	    insn_size <= 0 ||
	    insn_size / sizeof(struct bpf_insn) > MAX_BPF_INSNS ||
	    htab_size < 0 ||
	    htab_size / sizeof(struct bpf_table) > MAX_BPF_TABLES ||
	    strtab_size < 0 ||
	    strtab_size > MAX_BPF_STRTAB_SIZE ||
	    insn_size + htab_size + strtab_size + BPF_HEADER_SIZE != image_len) {
		pr_err("BPF program insn_size %d htab_size %d strtab_size %d\n",
		       insn_size, htab_size, strtab_size);
		return -E2BIG;
	}

	prog = kzalloc(sizeof(struct bpf_program), GFP_KERNEL);
	if (!prog)
		return -ENOMEM;

	prog->insn_cnt = insn_size / sizeof(struct bpf_insn);
	prog->cb = cb;

	prog->insns = kmalloc(insn_size, GFP_KERNEL);
	if (!prog->insns) {
		ret = -ENOMEM;
		goto free_prog;
	}

	memcpy(prog->insns, image + BPF_HEADER_SIZE, insn_size);

	if (htab_size) {
		prog->table_cnt = htab_size / sizeof(struct bpf_table);
		prog->tables = kmalloc(htab_size, GFP_KERNEL);
		if (!prog->tables) {
			ret = -ENOMEM;
			goto free_insns;
		}
		memcpy(prog->tables,
		       image + BPF_HEADER_SIZE + insn_size,
		       htab_size);
	}

	if (strtab_size) {
		prog->strtab_size = strtab_size;
		prog->strtab = kmalloc(strtab_size, GFP_KERNEL);
		if (!prog->strtab) {
			ret = -ENOMEM;
			goto free_tables;
		}
		memcpy(prog->strtab,
		       image + BPF_HEADER_SIZE + insn_size + htab_size,
		       strtab_size);
	}

	/* verify BPF program */
	ret = bpf_check(prog);
	if (ret)
		goto free_strtab;

	/* compile it (map BPF insns to native hw insns) */
	bpf_compile(prog);

	*p_prog = prog;

	return 0;

free_strtab:
	kfree(prog->strtab);
free_tables:
	kfree(prog->tables);
free_insns:
	kfree(prog->insns);
free_prog:
	kfree(prog);
	return ret;
}
EXPORT_SYMBOL(bpf_load_image);

void bpf_free(struct bpf_program *prog)
{
	if (!prog)
		return;
	__bpf_free(prog);
}
EXPORT_SYMBOL(bpf_free);

