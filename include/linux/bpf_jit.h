/* 64-bit BPF is Copyright (c) 2011-2013, PLUMgrid, http://plumgrid.com */

#ifndef __LINUX_BPF_JIT_H__
#define __LINUX_BPF_JIT_H__

#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/bpf.h>

/*
 * type of value stored in a BPF register or
 * passed into function as an argument or
 * returned from the function
 */
enum bpf_reg_type {
	INVALID_PTR,  /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,   /* reg points to bpf_context */
	PTR_TO_TABLE, /* reg points to table element */
	PTR_TO_TABLE_CONDITIONAL, /* points to table element or NULL */
	PTR_TO_STACK,     /* reg == frame_pointer */
	PTR_TO_STACK_IMM, /* reg == frame_pointer + imm */
	PTR_TO_STACK_IMM_TABLE_KEY, /* pointer to stack used as table key */
	PTR_TO_STACK_IMM_TABLE_ELEM, /* pointer to stack used as table elem */
	RET_INTEGER, /* function returns integer */
	RET_VOID,    /* function returns void */
	CONST_ARG,    /* function expects integer constant argument */
	CONST_ARG_TABLE_ID, /* int const argument that is used as table_id */
	/*
	 * int const argument indicating number of bytes accessed from stack
	 * previous function argument must be ptr_to_stack_imm
	 */
	CONST_ARG_STACK_IMM_SIZE,
};

/* BPF function prototype */
struct bpf_func_proto {
	enum bpf_reg_type ret_type;
	enum bpf_reg_type arg1_type;
	enum bpf_reg_type arg2_type;
	enum bpf_reg_type arg3_type;
	enum bpf_reg_type arg4_type;
};

/* struct bpf_context access type */
enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

struct bpf_context_access {
	int size;
	enum bpf_access_type type;
};

struct bpf_callbacks {
	/* execute BPF func_id with given registers */
	void (*execute_func)(char *strtab, int id, u64 *regs);

	/* return address of func_id suitable to be called from JITed program */
	void *(*jit_select_func)(char *strtab, int id);

	/* return BPF function prototype for verification */
	const struct bpf_func_proto* (*get_func_proto)(char *strtab, int id);

	/* return expected bpf_context access size and permissions
	 * for given byte offset within bpf_context */
	const struct bpf_context_access *(*get_context_access)(int off);
};

struct bpf_program {
	int   insn_cnt;
	int   table_cnt;
	int   strtab_size;
	struct bpf_insn *insns;
	struct bpf_table *tables;
	char *strtab;
	struct bpf_callbacks *cb;
	void (*jit_image)(struct bpf_context *ctx);
	struct work_struct work;
};
/*
 * BPF image format:
 * 4 bytes "bpf\0"
 * 4 bytes - size of insn section in bytes
 * 4 bytes - size of table definition section in bytes
 * 4 bytes - size of strtab section in bytes
 * bpf insns: one or more of 'struct bpf_insn'
 * hash table definitions: zero or more of 'struct bpf_table'
 * string table: zero separated ascii strings
 *
 * bpf_load_image() - load BPF image, setup callback extensions
 * and run through verifier
 */
int bpf_load_image(const char *image, int image_len, struct bpf_callbacks *cb,
		   struct bpf_program **prog);

/* free BPF program */
void bpf_free(struct bpf_program *prog);

/* execture BPF program */
void bpf_run(struct bpf_program *prog, struct bpf_context *ctx);

/* verify correctness of BPF program */
int bpf_check(struct bpf_program *prog);

/* pr_info one BPF instructions and registers */
void pr_info_bpf_insn(struct bpf_insn *insn, u64 *regs);

static inline void free_bpf_program(struct bpf_program *prog)
{
	kfree(prog->strtab);
	kfree(prog->tables);
	kfree(prog->insns);
	kfree(prog);
}
#if defined(CONFIG_BPF64_JIT)
void bpf_compile(struct bpf_program *prog);
void __bpf_free(struct bpf_program *prog);
#else
static inline void bpf_compile(struct bpf_program *prog)
{
}
static inline void __bpf_free(struct bpf_program *prog)
{
	free_bpf_program(prog);
}
#endif

#endif
