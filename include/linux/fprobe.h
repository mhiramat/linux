/* SPDX-License-Identifier: GPL-2.0 */
/* Simple ftrace probe wrapper */
#ifndef _LINUX_FPROBE_H
#define _LINUX_FPROBE_H

#include <linux/compiler.h>
#include <linux/ftrace.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include <asm/fprobe.h>

struct fprobe;
typedef int (*fprobe_entry_cb)(struct fprobe *fp, unsigned long entry_ip,
			       unsigned long ret_ip, struct ftrace_regs *regs,
			       void *entry_data);

typedef void (*fprobe_exit_cb)(struct fprobe *fp, unsigned long entry_ip,
			       unsigned long ret_ip, struct ftrace_regs *regs,
			       void *entry_data);

/**
 * strcut fprobe_hlist_node - address based hash list node for fprobe.
 *
 * @hlist: The hlist node for address search hash table.
 * @addr: The address represented by this.
 * @fp: The fprobe which owns this.
 */
struct fprobe_hlist_node {
	struct hlist_node	hlist;
	unsigned long		addr;
	struct fprobe		*fp;
};

/**
 * struct fprobe_hlist - hash list nodes for fprobe.
 *
 * @hlist: The hlist node for existence checking hash table.
 * @rcu: rcu_head for RCU deferred release.
 * @fp: The fprobe which owns this fprobe_hlist.
 * @size: The size of @array.
 * @array: The fprobe_hlist_node for each address to probe.
 */
struct fprobe_hlist {
	struct hlist_node		hlist;
	struct rcu_head			rcu;
	struct fprobe			*fp;
	int				size;
	struct fprobe_hlist_node	array[];
};

/**
 * struct fprobe - ftrace based probe.
 *
 * @nmissed: The counter for missing events.
 * @flags: The status flag.
 * @entry_data_size: The private data storage size.
 * @entry_handler: The callback function for function entry.
 * @exit_handler: The callback function for function exit.
 * @hlist_array: The fprobe_hlist for fprobe search from IP hash table.
 */
struct fprobe {
	unsigned long		nmissed;
	unsigned int		flags;
	size_t			entry_data_size;

	fprobe_entry_cb entry_handler;
	fprobe_exit_cb  exit_handler;

	struct fprobe_hlist	*hlist_array;
};

/* This fprobe is soft-disabled. */
#define FPROBE_FL_DISABLED	1

/*
 * This fprobe handler will be shared with kprobes.
 * This flag must be set before registering.
 */
#define FPROBE_FL_KPROBE_SHARED	2

static inline bool fprobe_disabled(struct fprobe *fp)
{
	return (fp) ? fp->flags & FPROBE_FL_DISABLED : false;
}

static inline bool fprobe_shared_with_kprobes(struct fprobe *fp)
{
	return (fp) ? fp->flags & FPROBE_FL_KPROBE_SHARED : false;
}

#ifdef CONFIG_FPROBE
int register_fprobe(struct fprobe *fp, const char *filter, const char *notfilter);
int register_fprobe_ips(struct fprobe *fp, unsigned long *addrs, int num);
int register_fprobe_syms(struct fprobe *fp, const char **syms, int num);
int unregister_fprobe(struct fprobe *fp);
bool fprobe_is_registered(struct fprobe *fp);
#else
static inline int register_fprobe(struct fprobe *fp, const char *filter, const char *notfilter)
{
	return -EOPNOTSUPP;
}
static inline int register_fprobe_ips(struct fprobe *fp, unsigned long *addrs, int num)
{
	return -EOPNOTSUPP;
}
static inline int register_fprobe_syms(struct fprobe *fp, const char **syms, int num)
{
	return -EOPNOTSUPP;
}
static inline int unregister_fprobe(struct fprobe *fp)
{
	return -EOPNOTSUPP;
}
static inline bool fprobe_is_registered(struct fprobe *fp)
{
	return false;
}
#endif

/**
 * disable_fprobe() - Disable fprobe
 * @fp: The fprobe to be disabled.
 *
 * This will soft-disable @fp. Note that this doesn't remove the ftrace
 * hooks from the function entry.
 */
static inline void disable_fprobe(struct fprobe *fp)
{
	if (fp)
		fp->flags |= FPROBE_FL_DISABLED;
}

/**
 * enable_fprobe() - Enable fprobe
 * @fp: The fprobe to be enabled.
 *
 * This will soft-enable @fp.
 */
static inline void enable_fprobe(struct fprobe *fp)
{
	if (fp)
		fp->flags &= ~FPROBE_FL_DISABLED;
}

/* The entry data size is 4 bits (=16) * sizeof(long) in maximum */
#define FPROBE_DATA_SIZE_BITS		4
#define MAX_FPROBE_DATA_SIZE_WORD	((1L << FPROBE_DATA_SIZE_BITS) - 1)
#define MAX_FPROBE_DATA_SIZE		(MAX_FPROBE_DATA_SIZE_WORD * sizeof(long))

#if defined(arch_encode_fprobe_header) && defined(arch_decode_fprobe_header)

/* The arch should encode fprobe_header info into one unsigned long */
#define FPROBE_HEADER_SIZE_IN_LONG	1

static inline bool write_fprobe_header(unsigned long *stack,
					struct fprobe *fp, unsigned int size_words)
{
	unsigned long val = arch_encode_fprobe_header(fp, size_words);

	if (!val)
		return false;

	*stack = val;
	return true;
}

static inline void read_fprobe_header(unsigned long *stack,
					struct fprobe **fp, unsigned int *size_words)
{
	arch_decode_fprobe_header(*stack, fp, size_words);
}
#else
/* Generic fprobe_header, which is safe for 32bit arch */
struct __fprobe_header {
	struct fprobe *fp;
	unsigned long size_words;
} __packed;

#define FPROBE_HEADER_SIZE_IN_LONG	SIZE_IN_LONG(sizeof(struct __fprobe_header))

static inline bool write_fprobe_header(unsigned long *stack,
					struct fprobe *fp, unsigned int size_words)
{
	struct __fprobe_header *fph = (struct __fprobe_header *)stack;

	if (WARN_ON_ONCE(size_words > MAX_FPROBE_DATA_SIZE_WORD))
		return false;

	fph->fp = fp;
	fph->size_words = size_words;
	return true;
}

static inline void read_fprobe_header(unsigned long *stack,
					struct fprobe **fp, unsigned int *size_words)
{
	struct __fprobe_header *fph = (struct __fprobe_header *)stack;

	*fp = fph->fp;
	*size_words = fph->size_words;
}
#endif /* CONFIG_HAVE_ARCH_FPROBE_HEADER */

#endif
