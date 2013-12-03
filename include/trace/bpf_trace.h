/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_KERNEL_BPF_TRACE_H
#define _LINUX_KERNEL_BPF_TRACE_H

#include <linux/ptrace.h>

struct bpf_context {
	struct pt_regs regs;
};

void *bpf_load_pointer(void *unsafe_ptr);
long bpf_memcmp(void *unsafe_ptr, void *safe_ptr, long size);
void bpf_dump_stack(struct bpf_context *ctx);
void bpf_trace_printk(char *fmt, long fmt_size,
		      long arg1, long arg2, long arg3);
void *bpf_table_lookup(struct bpf_context *ctx, long table_id, const void *key);
long bpf_table_update(struct bpf_context *ctx, long table_id, const void *key,
		      const void *leaf);

extern struct bpf_callbacks bpf_trace_cb;

#endif /* _LINUX_KERNEL_BPF_TRACE_H */
