// SPDX-License-Identifier: GPL-2.0
/*
 * trace_boot.c
 * Tracing kernel boot-time
 */

#define pr_fmt(fmt)	"trace_boot: " fmt

#include <linux/ftrace.h>
#include <linux/init.h>
#include <linux/skc.h>

#include "trace.h"

#define MAX_BUF_LEN 256

extern int trace_set_options(struct trace_array *tr, char *option);
extern enum ftrace_dump_mode ftrace_dump_on_oops;
extern int __disable_trace_on_warning;
extern int tracing_set_tracer(struct trace_array *tr, const char *buf);
extern void __init trace_init_tracepoint_printk(void);
extern ssize_t tracing_resize_ring_buffer(struct trace_array *tr,
					  unsigned long size, int cpu_id);
extern struct trace_array *trace_array_create(const char *name);
extern int tracing_set_cpumask(struct trace_array *tr,
				cpumask_var_t tracing_cpumask_new);

static void __init
trace_boot_set_instance_options(struct trace_array *tr, struct skc_node *node)
{
	struct skc_node *anode;
	const char *p;
	char buf[MAX_BUF_LEN];
	unsigned long v = 0;

	/* Common ftrace options */
	skc_node_for_each_array_value(node, "options", anode, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("String is too long: %s\n", p);
			continue;
		}

		if (trace_set_options(tr, buf) < 0)
			pr_err("Failed to set option: %s\n", buf);
	}

	p = skc_node_find_value(node, "trace_clock", NULL);
	if (p && *p != '\0') {
		if (tracing_set_clock(tr, p) < 0)
			pr_err("Failed to set trace clock: %s\n", p);
	}

	p = skc_node_find_value(node, "buffer_size", NULL);
	if (p && *p != '\0') {
		v = memparse(p, NULL);
		if (v < PAGE_SIZE)
			pr_err("Buffer size is too small: %s\n", p);
		if (tracing_resize_ring_buffer(tr, v, RING_BUFFER_ALL_CPUS) < 0)
			pr_err("Failed to resize trace buffer to %s\n", p);
	}

	p = skc_node_find_value(node, "cpumask", NULL);
	if (p && *p != '\0') {
		cpumask_var_t new_mask;

		if (alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
			if (cpumask_parse(p, new_mask) < 0 ||
			    tracing_set_cpumask(tr, new_mask) < 0)
				pr_err("Failed to set new CPU mask %s\n", p);
			free_cpumask_var(new_mask);
		}
	}
}

static void __init
trace_boot_set_global_options(struct trace_array *tr, struct skc_node *node)
{
	unsigned long v = 0;
	const char *p;
	int err;

	/* Command line boot options */
	p = skc_node_find_value(node, "dump_on_oops", NULL);
	if (p) {
		err = kstrtoul(p, 0, &v);
		if (err || v == 1)
			ftrace_dump_on_oops = DUMP_ALL;
		else if (!err && v == 2)
			ftrace_dump_on_oops = DUMP_ORIG;
	}

	if (skc_node_find_value(node, "traceoff_on_warning", NULL))
		__disable_trace_on_warning = 1;

	if (skc_node_find_value(node, "tp_printk", NULL))
		trace_init_tracepoint_printk();

	if (skc_node_find_value(node, "alloc_snapshot", NULL))
		if (tracing_alloc_snapshot() < 0)
			pr_err("Failed to allocate snapshot buffer\n");
}

#ifdef CONFIG_EVENT_TRACING
extern int ftrace_set_clr_event(struct trace_array *tr, char *buf, int set);
extern int trigger_process_regex(struct trace_event_file *file, char *buff);

static void __init
trace_boot_enable_events(struct trace_array *tr, struct skc_node *node)
{
	struct skc_node *anode;
	char buf[MAX_BUF_LEN];
	const char *p;

	skc_node_for_each_array_value(node, "events", anode, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("String is too long: %s\n", p);
			continue;
		}

		if (ftrace_set_clr_event(tr, buf, 1) < 0)
			pr_err("Failed to enable event: %s\n", p);
	}
}

#ifdef CONFIG_KPROBE_EVENTS
extern int trace_kprobe_run_command(const char *command);

static int __init
trace_boot_add_kprobe_event(struct skc_node *node, const char *event)
{
	struct skc_node *anode;
	char buf[MAX_BUF_LEN];
	const char *val;
	char *p;
	int len;

	len = snprintf(buf, ARRAY_SIZE(buf) - 1, "p:kprobes/%s ", event);
	if (len >= ARRAY_SIZE(buf)) {
		pr_err("Event name is too long: %s\n", event);
		return -E2BIG;
	}
	p = buf + len;
	len = ARRAY_SIZE(buf) - len;

	skc_node_for_each_array_value(node, "probes", anode, val) {
		if (strlcpy(p, val, len) >= len) {
			pr_err("Probe definition is too long: %s\n", val);
			return -E2BIG;
		}
		if (trace_kprobe_run_command(buf) < 0) {
			pr_err("Failed to add probe: %s\n", buf);
			return -EINVAL;
		}
	}

	return 0;
}
#else
static inline int __init
trace_boot_add_kprobe_event(struct skc_node *node, const char *event)
{
	pr_err("Kprobe event is not supported.\n");
	return -ENOTSUPP;
}
#endif

#ifdef CONFIG_HIST_TRIGGERS
extern int synth_event_run_command(const char *command);

static int __init
trace_boot_add_synth_event(struct skc_node *node, const char *event)
{
	struct skc_node *anode;
	char buf[MAX_BUF_LEN], *q;
	const char *p;
	int len, delta, ret;

	len = ARRAY_SIZE(buf);
	delta = snprintf(buf, len, "%s", event);
	if (delta >= len) {
		pr_err("Event name is too long: %s\n", event);
		return -E2BIG;
	}
	len -= delta; q = buf + delta;

	skc_node_for_each_array_value(node, "fields", anode, p) {
		delta = snprintf(q, len, " %s;", p);
		if (delta >= len) {
			pr_err("fields string is too long: %s\n", p);
			return -E2BIG;
		}
		len -= delta; q += delta;
	}

	ret = synth_event_run_command(buf);
	if (ret < 0)
		pr_err("Failed to add synthetic event: %s\n", buf);


	return ret;
}
#else
static inline int __init
trace_boot_add_synth_event(struct skc_node *node, const char *event)
{
	pr_err("Synthetic event is not supported.\n");
	return -ENOTSUPP;
}
#endif

static void __init
trace_boot_init_one_event(struct trace_array *tr, struct skc_node *gnode,
			  struct skc_node *enode)
{
	struct trace_event_file *file;
	struct skc_node *anode;
	char buf[MAX_BUF_LEN];
	const char *p, *group, *event;

	group = skc_node_get_data(gnode);
	event = skc_node_get_data(enode);

	if (!strcmp(group, "kprobes"))
		if (trace_boot_add_kprobe_event(enode, event) < 0)
			return;
	if (!strcmp(group, "synthetic"))
		if (trace_boot_add_synth_event(enode, event) < 0)
			return;

	mutex_lock(&event_mutex);
	file = find_event_file(tr, group, event);
	if (!file) {
		pr_err("Failed to find event: %s:%s\n", group, event);
		goto out;
	}

	p = skc_node_find_value(enode, "filter", NULL);
	if (p && *p != '\0') {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf))
			pr_err("filter string is too long: %s\n", p);
		else if (apply_event_filter(file, buf) < 0)
			pr_err("Failed to apply filter: %s\n", buf);
	}

	skc_node_for_each_array_value(enode, "actions", anode, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf))
			pr_err("action string is too long: %s\n", p);
		else if (trigger_process_regex(file, buf) < 0)
			pr_err("Failed to apply an action: %s\n", buf);
	}

	if (skc_node_find_value(enode, "enable", NULL)) {
		if (trace_event_enable_disable(file, 1, 0) < 0)
			pr_err("Failed to enable event node: %s:%s\n",
				group, event);
	}
out:
	mutex_unlock(&event_mutex);
}

static void __init
trace_boot_init_events(struct trace_array *tr, struct skc_node *node)
{
	struct skc_node *gnode, *enode;

	node = skc_node_find_child(node, "event");
	if (!node)
		return;
	/* per-event key starts with "event.GROUP.EVENT" */
	skc_node_for_each_child(node, gnode)
		skc_node_for_each_child(gnode, enode)
			trace_boot_init_one_event(tr, gnode, enode);
}
#else
#define trace_boot_enable_events(tr, node) do {} while (0)
#define trace_boot_init_events(tr, node) do {} while (0)
#endif

static void __init
trace_boot_enable_tracer(struct trace_array *tr, struct skc_node *node)
{
	const char *p;

	p = skc_node_find_value(node, "tracer", NULL);
	if (p && *p != '\0') {
		if (tracing_set_tracer(tr, p) < 0)
			pr_err("Failed to set given tracer: %s\n", p);
	}
}

static void __init
trace_boot_init_one_instance(struct trace_array *tr, struct skc_node *node)
{
	trace_boot_set_instance_options(tr, node);
	trace_boot_init_events(tr, node);
	trace_boot_enable_events(tr, node);
	trace_boot_enable_tracer(tr, node);
}

static void __init
trace_boot_init_instances(struct skc_node *node)
{
	struct skc_node *inode;
	struct trace_array *tr;
	const char *p;

	node = skc_node_find_child(node, "instance");
	if (!node)
		return;

	skc_node_for_each_child(node, inode) {
		p = skc_node_get_data(inode);
		if (!p || *p == '\0')
			continue;

		tr = trace_array_create(p);
		if (IS_ERR(tr)) {
			pr_err("Failed to create instance %s\n", p);
			continue;
		}
		trace_boot_init_one_instance(tr, inode);
	}
}

static int __init trace_boot_init(void)
{
	struct skc_node *trace_node;
	struct trace_array *tr;

	trace_node = skc_find_node("ftrace");
	if (!trace_node)
		return 0;

	tr = top_trace_array();
	if (!tr)
		return 0;

	trace_boot_set_global_options(tr, trace_node);
	/* Global trace array is also one instance */
	trace_boot_init_one_instance(tr, trace_node);
	trace_boot_init_instances(trace_node);

	return 0;
}

fs_initcall(trace_boot_init);
