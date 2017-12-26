// SPDX-License-Identifier: GPL-2.0
/*
 * fail_function.c: Function-based error injection
 */
#include <linux/error-injection.h>
#include <linux/debugfs.h>
#include <linux/fault-inject.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static int fei_kprobe_handler(struct kprobe *kp, struct pt_regs *regs);

static DEFINE_MUTEX(fei_lock);
static struct {
	struct kprobe kp;
	unsigned long retval;
	struct fault_attr attr;
} fei_attr = {
	.kp = { .pre_handler = fei_kprobe_handler, },
	.retval = (unsigned long)-EINVAL,
	.attr = FAULT_ATTR_INITIALIZER,
};

static int fei_kprobe_handler(struct kprobe *kp, struct pt_regs *regs)
{
	if (should_fail(&fei_attr.attr, 1)) {
		regs_set_return_value(regs, fei_attr.retval);
		override_function_with_return(regs);
		/* Kprobe specific fixup */
		reset_current_kprobe();
		preempt_enable_no_resched();
		return 1;
	}

	return 0;
}
NOKPROBE_SYMBOL(fei_kprobe_handler)

static unsigned long adjust_error_retval(unsigned long addr, unsigned long retv)
{
	switch (get_injectable_error_type(addr)) {
	case ERROR_RET_NULL:
		if (retv != 0)
			return 0;
		break;
	case ERROR_RET_ERRNO:
		if (retv < (unsigned long)-MAX_ERRNO)
			return (unsigned long)-EINVAL;
		break;
	case ERROR_RET_ERR_NULL:
		if (retv != 0 && retv < (unsigned long)-MAX_ERRNO)
			return (unsigned long)-EINVAL;
		break;
	}

	return retv;
}

static void *fei_seq_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&fei_lock);
	return *pos == 0 ? (void *)1 : NULL;
}

static void fei_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&fei_lock);
}

static void *fei_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static int fei_seq_show(struct seq_file *m, void *v)
{
	if (fei_attr.kp.addr)
		seq_printf(m, "%pf\n", fei_attr.kp.addr);
	else
		seq_puts(m, "# not specified\n");
	return 0;
}

static const struct seq_operations fei_seq_ops = {
	.start	= fei_seq_start,
	.next	= fei_seq_next,
	.stop	= fei_seq_stop,
	.show	= fei_seq_show,
};

static int fei_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &fei_seq_ops);
}

static ssize_t fei_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *ppos)
{
	unsigned long addr;
	char *buf, *sym;
	int ret;

	/* cut off if it is too long */
	if (count > KSYM_NAME_LEN)
		count = KSYM_NAME_LEN;
	buf = kmalloc(sizeof(char) * (count + 1), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, buffer, count)) {
		ret = -EFAULT;
		goto out;
	}
	buf[count] = '\0';
	sym = strstrip(buf);

	if (strlen(sym) == 0 || sym[0] == '0') {
		if (fei_attr.kp.addr) {
			unregister_kprobe(&fei_attr.kp);
			fei_attr.kp.addr = NULL;
			fei_attr.kp.flags = 0;
		}
		ret = count;
		goto out;
	}

	addr = kallsyms_lookup_name(sym);
	if (!addr) {
		ret = -EINVAL;
		goto out;
	}
	if (!within_error_injection_list(addr)) {
		ret = -ERANGE;
		goto out;
	}

	if (fei_attr.kp.addr) {
		unregister_kprobe(&fei_attr.kp);
		fei_attr.kp.addr = NULL;
	}
	fei_attr.kp.addr = (void *)addr;
	fei_attr.retval = adjust_error_retval(addr, fei_attr.retval);
	ret = register_kprobe(&fei_attr.kp);
	if (ret < 0)
		fei_attr.kp.addr = NULL;
	else
		ret = count;
out:
	kfree(buf);
	return ret;
}

static const struct file_operations fei_ops = {
	.open =		fei_open,
	.read =		seq_read,
	.write =	fei_write,
	.llseek =	seq_lseek,
	.release =	seq_release,
};

static int fei_retval_set(void *data, u64 val)
{
	unsigned long retv = (unsigned long)val;
	int err = 0;

	mutex_lock(&fei_lock);
	if (fei_attr.kp.addr) {
		if (adjust_error_retval((unsigned long)fei_attr.kp.addr,
					val) != retv)
			err = -EINVAL;
	}
	if (!err)
	       *(unsigned long *)data = val;
	mutex_unlock(&fei_lock);

        return err;
}

static int fei_retval_get(void *data, u64 *val)
{
        *val = *(unsigned long *)data;
        return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(fei_err_ops, fei_retval_get, fei_retval_set, "%llx\n");

static int __init fei_debugfs_init(void)
{
	struct dentry *dir;

	dir = fault_create_debugfs_attr("fail_function", NULL,
					&fei_attr.attr);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	/* injectable attribute is just a symlink of error_inject/list */
	if (!debugfs_create_symlink("injectable", dir,
				    "../error_injection/list"))
		goto error;

	if (!debugfs_create_file("inject", 0600, dir, NULL, &fei_ops))
		goto error;

	if (!debugfs_create_file("retval", 0600, dir, &fei_attr.retval,
				 &fei_err_ops))
		goto error;

	return 0;
error:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

late_initcall(fei_debugfs_init);
