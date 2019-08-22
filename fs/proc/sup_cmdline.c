// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/sup_cmdline - Supplemental kernel command line
 */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skc.h>
#include <linux/slab.h>

static char *saved_sup_cmdline;

static int skc_proc_show(struct seq_file *m, void *v)
{
	if (saved_sup_cmdline)
		seq_puts(m, saved_sup_cmdline);
	else
		seq_putc(m, '\n');
	return 0;
}

static int __init update_snprintf(char **dstp, size_t *sizep,
				  const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vsnprintf(*dstp, *sizep, fmt, args);
	va_end(args);

	if (*sizep && ret > 0) {
		*sizep -= ret;
		*dstp += ret;
	}

	return ret;
}

/* Return the needed total length if @size is 0 */
static int __init copy_skc_key_value_list(char *dst, size_t size)
{
	struct skc_node *leaf, *vnode;
	const char *val;
	int len = 0, ret = 0;
	char *key;

	key = kzalloc(SKC_KEYLEN_MAX, GFP_KERNEL);

	skc_for_each_key_value(leaf, val) {
		ret = skc_node_compose_key(leaf, key, SKC_KEYLEN_MAX);
		if (ret < 0)
			break;
		ret = update_snprintf(&dst, &size, "%s = ", key);
		if (ret < 0)
			break;
		len += ret;
		vnode = skc_node_get_child(leaf);
		if (vnode && skc_node_is_array(vnode)) {
			skc_array_for_each_value(vnode, val) {
				ret = update_snprintf(&dst, &size, "\"%s\"%s",
					val, vnode->next ? ", " : ";\n");
				if (ret < 0)
					goto out;
				len += ret;
			}
		} else {
			ret = update_snprintf(&dst, &size, "\"%s\";\n", val);
			if (ret < 0)
				break;
			len += ret;
		}
	}
out:
	kfree(key);

	return ret < 0 ? ret : len;
}

static int __init proc_skc_init(void)
{
	int len;

	len = copy_skc_key_value_list(NULL, 0);
	if (len < 0)
		return len;

	if (len > 0) {
		saved_sup_cmdline = kzalloc(len + 1, GFP_KERNEL);
		if (!saved_sup_cmdline)
			return -ENOMEM;

		len = copy_skc_key_value_list(saved_sup_cmdline, len + 1);
		if (len < 0) {
			kfree(saved_sup_cmdline);
			return len;
		}
	}

	proc_create_single("sup_cmdline", 0, NULL, skc_proc_show);

	return 0;
}
fs_initcall(proc_skc_init);
