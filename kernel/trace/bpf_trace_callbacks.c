/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf_jit.h>
#include <linux/uaccess.h>
#include <trace/bpf_trace.h>
#include "trace.h"

#define MAX_CTX_OFF sizeof(struct bpf_context)

static const struct bpf_context_access ctx_access[MAX_CTX_OFF] = {
#ifdef CONFIG_X86_64
	[offsetof(struct bpf_context, regs.di)] = {
		FIELD_SIZEOF(struct bpf_context, regs.di),
		BPF_READ
	},
	[offsetof(struct bpf_context, regs.si)] = {
		FIELD_SIZEOF(struct bpf_context, regs.si),
		BPF_READ
	},
	[offsetof(struct bpf_context, regs.dx)] = {
		FIELD_SIZEOF(struct bpf_context, regs.dx),
		BPF_READ
	},
	[offsetof(struct bpf_context, regs.cx)] = {
		FIELD_SIZEOF(struct bpf_context, regs.cx),
		BPF_READ
	},
#endif
};

static const struct bpf_context_access *get_context_access(int off)
{
	if (off >= MAX_CTX_OFF)
		return NULL;
	return &ctx_access[off];
}

void *bpf_load_pointer(void *unsafe_ptr)
{
	void *ptr = NULL;

	probe_kernel_read(&ptr, unsafe_ptr, sizeof(void *));
	return ptr;
}

long bpf_memcmp(void *unsafe_ptr, void *safe_ptr, long size)
{
	char buf[64];
	int err;

	if (size < 64) {
		err = probe_kernel_read(buf, unsafe_ptr, size);
		if (err)
			return err;
		return memcmp(buf, safe_ptr, size);
	}
	return -1;
}

void bpf_dump_stack(struct bpf_context *ctx)
{
	unsigned long flags;

	local_save_flags(flags);

	__trace_stack_regs(flags, 0, preempt_count(), (struct pt_regs *)ctx);
}

/*
 * limited trace_printk()
 * only %d %u %p %x conversion specifiers allowed
 */
void bpf_trace_printk(char *fmt, long fmt_size, long arg1, long arg2, long arg3)
{
	int fmt_cnt = 0;
	int i;

	/*
	 * bpf_check() guarantees that fmt points to bpf program stack and
	 * fmt_size bytes of it were initialized by bpf program
	 */
	if (fmt[fmt_size - 1] != 0)
		return;

	for (i = 0; i < fmt_size; i++)
		if (fmt[i] == '%') {
			if (i + 1 >= fmt_size)
				return;
			if (fmt[i + 1] != 'p' && fmt[i + 1] != 'd' &&
			    fmt[i + 1] != 'u' && fmt[i + 1] != 'x')
				return;
			fmt_cnt++;
		}
	if (fmt_cnt > 3)
		return;
	__trace_printk((unsigned long)__builtin_return_address(3), fmt,
		       arg1, arg2, arg3);
}


static const struct bpf_func_proto *get_func_proto(char *strtab, int id)
{
	if (!strcmp(strtab + id, "bpf_load_pointer")) {
		static const struct bpf_func_proto proto = {RET_INTEGER};
		return &proto;
	}
	if (!strcmp(strtab + id, "bpf_memcmp")) {
		static const struct bpf_func_proto proto = {RET_INTEGER,
			INVALID_PTR, PTR_TO_STACK_IMM,
			CONST_ARG_STACK_IMM_SIZE};
		return &proto;
	}
	if (!strcmp(strtab + id, "bpf_dump_stack")) {
		static const struct bpf_func_proto proto = {RET_VOID,
			PTR_TO_CTX};
		return &proto;
	}
	if (!strcmp(strtab + id, "bpf_trace_printk")) {
		static const struct bpf_func_proto proto = {RET_VOID,
			PTR_TO_STACK_IMM, CONST_ARG_STACK_IMM_SIZE};
		return &proto;
	}
	if (!strcmp(strtab + id, "bpf_table_lookup")) {
		static const struct bpf_func_proto proto = {
			PTR_TO_TABLE_CONDITIONAL, PTR_TO_CTX,
			CONST_ARG_TABLE_ID, PTR_TO_STACK_IMM_TABLE_KEY};
		return &proto;
	}
	if (!strcmp(strtab + id, "bpf_table_update")) {
		static const struct bpf_func_proto proto = {RET_INTEGER,
			PTR_TO_CTX, CONST_ARG_TABLE_ID,
			PTR_TO_STACK_IMM_TABLE_KEY,
			PTR_TO_STACK_IMM_TABLE_ELEM};
		return &proto;
	}
	return NULL;
}

static void execute_func(char *strtab, int id, u64 *regs)
{
	regs[R0] = 0;

	/*
	 * strcmp-approach is not efficient.
	 * TODO: optimize it for poor archs that don't have JIT yet
	 */
	if (!strcmp(strtab + id, "bpf_load_pointer")) {
		regs[R0] = (u64)bpf_load_pointer((void *)regs[R1]);
	} else if (!strcmp(strtab + id, "bpf_memcmp")) {
		regs[R0] = (u64)bpf_memcmp((void *)regs[R1], (void *)regs[R2],
					   (long)regs[R3]);
	} else if (!strcmp(strtab + id, "bpf_dump_stack")) {
		bpf_dump_stack((struct bpf_context *)regs[R1]);
	} else if (!strcmp(strtab + id, "bpf_trace_printk")) {
		bpf_trace_printk((char *)regs[R1], (long)regs[R2],
				 (long)regs[R3], (long)regs[R4],
				 (long)regs[R5]);
	} else {
		pr_err_once("trace cannot execute unknown bpf function %d '%s'\n",
			    id, strtab + id);
	}
}

static void *jit_select_func(char *strtab, int id)
{
	if (!strcmp(strtab + id, "bpf_load_pointer"))
		return bpf_load_pointer;

	if (!strcmp(strtab + id, "bpf_memcmp"))
		return bpf_memcmp;

	if (!strcmp(strtab + id, "bpf_dump_stack"))
		return bpf_dump_stack;

	if (!strcmp(strtab + id, "bpf_trace_printk"))
		return bpf_trace_printk;

	return NULL;
}

struct bpf_callbacks bpf_trace_cb = {
	execute_func, jit_select_func, get_func_proto, get_context_access
};

