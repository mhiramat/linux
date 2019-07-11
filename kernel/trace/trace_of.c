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

static void __init
trace_of_set_ftrace_options(struct trace_array *tr, struct device_node *node)
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

	if (of_find_property(node, "alloc-snapshot", NULL))
		if (tracing_alloc_snapshot() < 0)
			pr_err("Failed to allocate snapshot buffer\n");
}

#ifdef CONFIG_EVENT_TRACING
extern int ftrace_set_clr_event(struct trace_array *tr, char *buf, int set);

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
#else
#define trace_of_enable_events(tr, node) do {} while (0)
#endif

static void __init
trace_of_enable_tracer(struct trace_array *tr, struct device_node *node)
{
	const char *p;

	if (!of_property_read_string(node, "tracer", &p)) {
		if (tracing_set_tracer(tr, p) < 0)
			pr_err("Failed to set given tracer: %s\n", p);

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
	trace_of_enable_events(tr, trace_node);
	trace_of_enable_tracer(tr, trace_node);

end:
	of_node_put(trace_node);
	return 0;
}

fs_initcall(trace_of_init);
