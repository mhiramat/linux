// SPDX-License-Identifier: GPL-2.0
/*
 * trace_of.c
 * devicetree tracing programming APIs
 */

#define pr_fmt(fmt)	"trace_of: " fmt

#include <linux/ftrace.h>
#include <linux/init.h>
#include <linux/of.h>

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
trace_of_set_instance_options(struct trace_array *tr, struct device_node *node)
{
	struct property *prop;
	const char *p;
	char buf[MAX_BUF_LEN];
	u32 v = 0;
	int err;

	/* Common ftrace options */
	of_property_for_each_string(node, "options", prop, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("String is too long: %s\n", p);
			continue;
		}

		if (trace_set_options(tr, buf) < 0)
			pr_err("Failed to set option: %s\n", buf);
	}

	err = of_property_read_string(node, "trace-clock", &p);
	if (!err) {
		if (tracing_set_clock(tr, p) < 0)
			pr_err("Failed to set trace clock: %s\n", p);
	}

	/* This accepts per-cpu buffer size in KB */
	err = of_property_read_u32_index(node, "buffer-size-kb", 0, &v);
	if (!err) {
		v <<= 10;	/* KB to Byte */
		if (v < PAGE_SIZE)
			pr_err("Buffer size is too small: %d KB\n", v >> 10);
		if (tracing_resize_ring_buffer(tr, v, RING_BUFFER_ALL_CPUS) < 0)
			pr_err("Failed to resize trace buffer to %d KB\n",
				v >> 10);
	}

	err = of_property_read_string(node, "cpumask", &p);
	if (!err) {
		cpumask_var_t new_mask;

		if (alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
			if (cpumask_parse(p, new_mask) < 0 ||
			    tracing_set_cpumask(tr, new_mask) < 0)
				pr_err("Failed to set new CPU mask %s\n", p);
			free_cpumask_var(new_mask);
		}
	}
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern unsigned int fgraph_max_depth;
extern struct ftrace_hash *ftrace_graph_copy_hash(bool enable);
extern int ftrace_graph_set_hash(struct ftrace_hash *hash, char *buffer);
extern int ftrace_graph_apply_hash(struct ftrace_hash *hash, bool enable);
extern void free_ftrace_hash(struct ftrace_hash *hash);

static void __init
trace_of_set_fgraph_filter(struct device_node *node, const char *property,
			   bool enable)
{
	struct ftrace_hash *hash;
	struct property *prop;
	const char *p;
	char buf[MAX_BUF_LEN];
	int err;

	if (!of_find_property(node, property, NULL))
		return;

	/* Get current filter hash */
	hash = ftrace_graph_copy_hash(enable);
	if (!hash) {
		pr_err("Failed to copy hash\n");
		return;
	}

	of_property_for_each_string(node, property, prop, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("filter string is too long: %s\n", p);
			goto free_hash;
		}
		err = ftrace_graph_set_hash(hash, buf);
		if (err) {
			pr_err("Failed to add %s: %s\n", property, buf);
			goto free_hash;
		}
	}

	if (ftrace_graph_apply_hash(hash, enable) < 0) {
		pr_err("Failed to apply new hash\n");
		goto free_hash;
	}

	return;

free_hash:
	free_ftrace_hash(hash);
}

static void __init
trace_of_set_fgraph_options(struct device_node *node)
{
	u32 v = 0;

	trace_of_set_fgraph_filter(node, "fgraph-filters", true);
	trace_of_set_fgraph_filter(node, "fgraph-notraces", false);

	if (!of_property_read_u32_index(node, "fgraph-max-depth", 0, &v))
		fgraph_max_depth = (unsigned int)v;
}
#else
#define trace_of_set_fgraph_options(node) do {} while (0)
#endif

static void __init
trace_of_set_ftrace_options(struct trace_array *tr, struct device_node *node)
{
	u32 v = 0;
	int err;

	/* Command line boot options */
	if (of_find_property(node, "dump-on-oops", NULL)) {
		err = of_property_read_u32_index(node, "dump-on-oops", 0, &v);
		if (err || v == 1)
			ftrace_dump_on_oops = DUMP_ALL;
		else if (!err && v == 2)
			ftrace_dump_on_oops = DUMP_ORIG;
	}

	if (of_find_property(node, "traceoff-on-warning", NULL))
		__disable_trace_on_warning = 1;

	if (of_find_property(node, "tp-printk", NULL))
		trace_init_tracepoint_printk();

	if (of_find_property(node, "alloc-snapshot", NULL))
		if (tracing_alloc_snapshot() < 0)
			pr_err("Failed to allocate snapshot buffer\n");

	/* function graph filters are global settings. */
	trace_of_set_fgraph_options(node);

	trace_of_set_instance_options(tr, node);
}

#ifdef CONFIG_EVENT_TRACING
extern int ftrace_set_clr_event(struct trace_array *tr, char *buf, int set);
extern int trigger_process_regex(struct trace_event_file *file, char *buff);

static void __init
trace_of_enable_events(struct trace_array *tr, struct device_node *node)
{
	struct property *prop;
	char buf[MAX_BUF_LEN];
	const char *p;

	of_property_for_each_string(node, "events", prop, p) {
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
trace_of_add_kprobe_event(struct device_node *node,
			  const char *group, const char *event)
{
	struct property *prop;
	char buf[MAX_BUF_LEN];
	const char *p;
	char *q;
	int len, ret;

	len = snprintf(buf, ARRAY_SIZE(buf) - 1, "p:%s/%s ", group, event);
	if (len >= ARRAY_SIZE(buf)) {
		pr_err("Event name is too long: %s\n", event);
		return -E2BIG;
	}
	q = buf + len;
	len = ARRAY_SIZE(buf) - len;

	of_property_for_each_string(node, "probes", prop, p) {
		if (strlcpy(q, p, len) >= len) {
			pr_err("Probe definition is too long: %s\n", p);
			return -E2BIG;
		}
		ret = trace_kprobe_run_command(buf);
		if (ret < 0) {
			pr_err("Failed to add probe: %s\n", buf);
			return ret;
		}
	}

	return 0;
}
#else
static inline int __init
trace_of_add_kprobe_event(struct device_node *node,
			  const char *group, const char *event)
{
	pr_err("Kprobe event is not supported.\n");
	return -ENOTSUPP;
}
#endif

#ifdef CONFIG_HIST_TRIGGERS
extern int synth_event_run_command(const char *command);

static int __init
trace_of_add_synth_event(struct device_node *node, const char *event)
{
	struct property *prop;
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

	of_property_for_each_string(node, "fields", prop, p) {
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
trace_of_add_synth_event(struct device_node *node, const char *event)
{
	pr_err("Synthetic event is not supported.\n");
	return -ENOTSUPP;
}
#endif

static void __init
trace_of_init_one_event(struct trace_array *tr, struct device_node *node)
{
	struct trace_event_file *file;
	struct property *prop;
	char buf[MAX_BUF_LEN];
	const char *p, *group;
	char *event;
	int err;

	if (!of_node_name_prefix(node, "event"))
		return;

	err = of_property_read_string(node, "event", &p);
	if (err) {
		pr_err("Failed to find event on %s\n", of_node_full_name(node));
		return;
	}

	err = strlcpy(buf, p, ARRAY_SIZE(buf));
	if (err >= ARRAY_SIZE(buf)) {
		pr_err("Event name is too long: %s\n", p);
		return;
	}
	event = buf;

	group = strsep(&event, ":");

	/* Generates kprobe/synth event at first */
	if (of_find_property(node, "probes", NULL)) {
		if (of_find_property(node, "fields", NULL)) {
			pr_err("Error: %s node has both probes and fields\n",
				of_node_full_name(node));
			return;
		}
		if (!event) {
			event = buf;
			group = "kprobes";
		}
		if (trace_of_add_kprobe_event(node, group, event) < 0)
			return;
	} else if (of_find_property(node, "fields", NULL)) {
		if (!event)
			event = buf;
		else if (strcmp(group, "synthetic") != 0) {
			pr_err("Synthetic event must be in synthetic group\n");
			return;
		}
		if (trace_of_add_synth_event(node, event) < 0)
			return;
		group = "synthetic";
	} else {
		if (!event) {
			pr_err("%s has no group name\n", buf);
			return;
		}
	}

	mutex_lock(&event_mutex);
	file = find_event_file(tr, group, event);
	if (!file) {
		pr_err("Failed to find event: %s:%s\n", group, event);
		return;
	}

	err = of_property_read_string(node, "filter", &p);
	if (!err) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("filter string is too long: %s\n", p);
			return;
		}

		if (apply_event_filter(file, buf) < 0) {
			pr_err("Failed to apply filter: %s\n", buf);
			return;
		}
	}

	of_property_for_each_string(node, "actions", prop, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("action string is too long: %s\n", p);
			continue;
		}

		if (trigger_process_regex(file, buf) < 0)
			pr_err("Failed to apply an action: %s\n", buf);
	}

	if (of_property_read_bool(node, "enable")) {
		if (trace_event_enable_disable(file, 1, 0) < 0)
			pr_err("Failed to enable event node: %s\n",
				of_node_full_name(node));
	}
	mutex_unlock(&event_mutex);
}

static void __init
trace_of_init_events(struct trace_array *tr, struct device_node *node)
{
	struct device_node *enode;

	for_each_child_of_node(node, enode)
		trace_of_init_one_event(tr, enode);
}
#else
#define trace_of_enable_events(tr, node) do {} while (0)
#define trace_of_init_events(tr, node) do {} while (0)
#endif

#ifdef CONFIG_FUNCTION_TRACER
extern bool ftrace_filter_param __initdata;
extern int ftrace_set_filter(struct ftrace_ops *ops, unsigned char *buf,
			     int len, int reset);
extern int ftrace_set_notrace(struct ftrace_ops *ops, unsigned char *buf,
			     int len, int reset);

static void __init
trace_of_set_ftrace_filter(struct ftrace_ops *ops, const char *property,
			   struct device_node *node)
{
	struct property *prop;
	const char *p;
	char buf[MAX_BUF_LEN];
	int err;

	of_property_for_each_string(node, property, prop, p) {
		if (strlcpy(buf, p, ARRAY_SIZE(buf)) >= ARRAY_SIZE(buf)) {
			pr_err("filter string is too long: %s\n", p);
			return;
		}
		err = ftrace_set_filter(ops, buf, strlen(buf), 0);
		if (err) {
			pr_err("Failed to add %s: %s\n", property, buf);
			return;
		}
		ftrace_filter_param = true;
	}
}
#else
#define trace_of_set_ftrace_filter(ops, prop, node) do {} while (0)
#endif

static void __init
trace_of_enable_tracer(struct trace_array *tr, struct device_node *node)
{
	const char *p;

	trace_of_set_ftrace_filter(tr->ops, "ftrace-filters", node);
	trace_of_set_ftrace_filter(tr->ops, "ftrace-notraces", node);

	if (!of_property_read_string(node, "tracer", &p)) {
		if (tracing_set_tracer(tr, p) < 0)
			pr_err("Failed to set given tracer: %s\n", p);

	}
}

static void __init
trace_of_init_instances(struct device_node *__node)
{
	struct device_node *node;
	struct trace_array *tr;
	const char *p;
	int err;

	for_each_child_of_node(__node, node) {
		if (!of_node_name_prefix(node, "instance"))
			continue;

		err = of_property_read_string(node, "instance", &p);
		if (err) {
			pr_err("Failed to get instance name on %s\n",
				of_node_full_name(node));
			continue;
		}

		tr = trace_array_create(p);
		if (IS_ERR(tr)) {
			pr_err("Failed to create instance %s\n", p);
			continue;
		}

		trace_of_set_instance_options(tr, node);
		trace_of_init_events(tr, node);
		trace_of_enable_events(tr, node);
		trace_of_enable_tracer(tr, node);
	}
}

static struct device_node * __init trace_of_find_ftrace_node(void)
{
	if (!of_chosen)
		return NULL;

	return of_find_node_by_name(of_chosen, "linux,ftrace");
}

static int __init trace_of_init(void)
{
	struct device_node *trace_node;
	struct trace_array *tr;

	trace_node = trace_of_find_ftrace_node();
	if (!trace_node)
		return 0;

	trace_node = of_node_get(trace_node);

	tr = top_trace_array();
	if (!tr)
		goto end;

	trace_of_set_ftrace_options(tr, trace_node);
	trace_of_init_events(tr, trace_node);
	trace_of_enable_events(tr, trace_node);
	trace_of_enable_tracer(tr, trace_node);
	trace_of_init_instances(trace_node);

end:
	of_node_put(trace_node);
	return 0;
}

fs_initcall(trace_of_init);
