/*
 * Architecture specific debugfs files
 *
 * Copyright (C) 2007, Intel Corp.
 *	Huang Ying <ying.huang@intel.com>
 *
 * This file is released under the GPLv2.
 */
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/ctype.h>

#include <asm/setup.h>
#include <asm/disasm.h>

struct dentry *arch_debugfs_dir;
EXPORT_SYMBOL(arch_debugfs_dir);

#ifdef CONFIG_DEBUG_BOOT_PARAMS
struct setup_data_node {
	u64 paddr;
	u32 type;
	u32 len;
};

static ssize_t setup_data_read(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct setup_data_node *node = file->private_data;
	unsigned long remain;
	loff_t pos = *ppos;
	struct page *pg;
	void *p;
	u64 pa;

	if (pos < 0)
		return -EINVAL;

	if (pos >= node->len)
		return 0;

	if (count > node->len - pos)
		count = node->len - pos;

	pa = node->paddr + sizeof(struct setup_data) + pos;
	pg = pfn_to_page((pa + count - 1) >> PAGE_SHIFT);
	if (PageHighMem(pg)) {
		p = ioremap_cache(pa, count);
		if (!p)
			return -ENXIO;
	} else
		p = __va(pa);

	remain = copy_to_user(user_buf, p, count);

	if (PageHighMem(pg))
		iounmap(p);

	if (remain)
		return -EFAULT;

	*ppos = pos + count;

	return count;
}

static const struct file_operations fops_setup_data = {
	.read		= setup_data_read,
	.open		= simple_open,
	.llseek		= default_llseek,
};

static int __init
create_setup_data_node(struct dentry *parent, int no,
		       struct setup_data_node *node)
{
	struct dentry *d, *type, *data;
	char buf[16];

	sprintf(buf, "%d", no);
	d = debugfs_create_dir(buf, parent);
	if (!d)
		return -ENOMEM;

	type = debugfs_create_x32("type", S_IRUGO, d, &node->type);
	if (!type)
		goto err_dir;

	data = debugfs_create_file("data", S_IRUGO, d, node, &fops_setup_data);
	if (!data)
		goto err_type;

	return 0;

err_type:
	debugfs_remove(type);
err_dir:
	debugfs_remove(d);
	return -ENOMEM;
}

static int __init create_setup_data_nodes(struct dentry *parent)
{
	struct setup_data_node *node;
	struct setup_data *data;
	int error = -ENOMEM;
	struct dentry *d;
	struct page *pg;
	u64 pa_data;
	int no = 0;

	d = debugfs_create_dir("setup_data", parent);
	if (!d)
		return -ENOMEM;

	pa_data = boot_params.hdr.setup_data;

	while (pa_data) {
		node = kmalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			goto err_dir;

		pg = pfn_to_page((pa_data+sizeof(*data)-1) >> PAGE_SHIFT);
		if (PageHighMem(pg)) {
			data = ioremap_cache(pa_data, sizeof(*data));
			if (!data) {
				kfree(node);
				error = -ENXIO;
				goto err_dir;
			}
		} else
			data = __va(pa_data);

		node->paddr = pa_data;
		node->type = data->type;
		node->len = data->len;
		error = create_setup_data_node(d, no, node);
		pa_data = data->next;

		if (PageHighMem(pg))
			iounmap(data);
		if (error)
			goto err_dir;
		no++;
	}

	return 0;

err_dir:
	debugfs_remove(d);
	return error;
}

static struct debugfs_blob_wrapper boot_params_blob = {
	.data		= &boot_params,
	.size		= sizeof(boot_params),
};

static int __init boot_params_kdebugfs_init(void)
{
	struct dentry *dbp, *version, *data;
	int error = -ENOMEM;

	dbp = debugfs_create_dir("boot_params", NULL);
	if (!dbp)
		return -ENOMEM;

	version = debugfs_create_x16("version", S_IRUGO, dbp,
				     &boot_params.hdr.version);
	if (!version)
		goto err_dir;

	data = debugfs_create_blob("data", S_IRUGO, dbp,
				   &boot_params_blob);
	if (!data)
		goto err_version;

	error = create_setup_data_nodes(dbp);
	if (error)
		goto err_data;

	return 0;

err_data:
	debugfs_remove(data);
err_version:
	debugfs_remove(version);
err_dir:
	debugfs_remove(dbp);
	return error;
}
#endif /* CONFIG_DEBUG_BOOT_PARAMS */

#ifdef CONFIG_DEBUG_X86_DISASSEMBLY
static DEFINE_MUTEX(disasm_lock);
static char disasm_funcname[KSYM_NAME_LEN];
static unsigned long disasm_addr;
static unsigned long disasm_size;
static void *disasm_pos;

static ssize_t disasm_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	ssize_t ret = count;
	char *c;

	if (count >= KSYM_NAME_LEN)
		return -E2BIG;

	mutex_lock(&disasm_lock);
	if (copy_from_user(disasm_funcname, buffer, count)) {
		ret = -EFAULT;
		goto end;
	}

	disasm_funcname[count] = '\0';
	c = strchr(disasm_funcname, '\n');
	if (c)
		*c = '\0';

	disasm_addr = (unsigned long)kallsyms_lookup_name(disasm_funcname);
	if (!disasm_addr)
		ret = -EINVAL;
end:
	mutex_unlock(&disasm_lock);

	return ret;
}

static void *disasm_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct insn insn;
	char kbuf[MAX_INSN_SIZE];
	void *p;

	if (!v)
		return NULL;

	p = (void *)recover_probed_instruction(kbuf, (unsigned long)v);
	kernel_insn_init(&insn, p);
	insn_get_length(&insn);
	v += insn.length;

	if ((unsigned long)v >= disasm_addr + disasm_size)
		return NULL;
	return v;
}

static void *disasm_seq_start(struct seq_file *m, loff_t *pos)
{
	unsigned long offs;
	const char *name;

	mutex_lock(&disasm_lock);
	if (!disasm_addr)
		return NULL;

	if (*pos == 0) {
		name = kallsyms_lookup(disasm_addr, &disasm_size, &offs, NULL,
					disasm_funcname);
		if (!name || offs != 0)
			return NULL;

		seq_printf(m, "<%s>:\n", name);
		return (void *)disasm_addr;
	} else
		return disasm_seq_next(m, disasm_pos, pos);
}

static void disasm_seq_stop(struct seq_file *m, void *v)
{
	disasm_pos = v;
	mutex_unlock(&disasm_lock);
}

#define DISASM_BUF_LEN	150

static int disasm_seq_show(struct seq_file *m, void *v)
{
	char buf[DISASM_BUF_LEN];
	u8 kbuf[MAX_INSN_SIZE];
	struct insn insn;
	void *p;

	p = (void *)recover_probed_instruction(kbuf, (unsigned long)v);
	kernel_insn_init(&insn, p);
	insn_get_length(&insn);
	insn.kaddr = v;
	snprint_assembly(buf, DISASM_BUF_LEN, &insn, DISASM_PR_ALL);
	seq_printf(m, "%s", buf);

	return 0;
}

static const struct seq_operations disasm_seq_ops = {
	.start	= disasm_seq_start,
	.next	= disasm_seq_next,
	.stop	= disasm_seq_stop,
	.show	= disasm_seq_show,
};

static int disasm_open(struct inode *inode, struct file *file)
{
	/* Currently we just ignore O_APPEND */
	return seq_open(file, &disasm_seq_ops);
}

static const struct file_operations disasm_fops = {
	.open		= disasm_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.write		= disasm_write,
};

static int __init disassembly_kdebugfs_init(void)
{
	debugfs_create_file("disassembly", S_IRUSR | S_IWUSR,
		 arch_debugfs_dir, NULL, &disasm_fops);
	return 0;
}

#endif /* CONFIG_DEBUG_X86_DISASSEMBLY */

static int __init arch_kdebugfs_init(void)
{
	int error = 0;

	arch_debugfs_dir = debugfs_create_dir("x86", NULL);
	if (!arch_debugfs_dir)
		return -ENOMEM;

#ifdef CONFIG_DEBUG_X86_DISASSEMBLY
	error = disassembly_kdebugfs_init();
	if (error)
		return error;
#endif
#ifdef CONFIG_DEBUG_BOOT_PARAMS
	error = boot_params_kdebugfs_init();
#endif

	return error;
}
arch_initcall(arch_kdebugfs_init);
