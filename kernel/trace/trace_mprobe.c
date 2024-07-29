// SPDX-License-Identifier: GPL-2.0
/*
 * Monitoring metrics trace probe
 *
 * Copyright 2024 Google.
 *
 */

#define pr_fmt(fmt)	"trace_mprobe: " fmt

#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <linux/cpumask.h>
#include <linux/kernel_stat.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */

#include "trace_dynevent.h"
#include "trace_probe.h"
#include "trace_probe_tmpl.h"
#include "trace_probe_kernel.h"

#define MPROBE_EVENT_SYSTEM "mprobes"

struct trace_mprobe {
	struct dyn_event	devent;
	struct work_struct	work;
	struct timer_list	timer;
	unsigned long		interval;
	unsigned long		last;
	struct trace_probe	tp;

	void (*monitor)(struct trace_mprobe *mp);
};

/* Monitor /proc/stat worker */
static void monitor_stat(struct trace_mprobe *mp, void *buffer)
{
	struct kernel_cpustat total = {};
	int i;

	for_each_possible_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;

		kcpustat_cpu_fetch(&kcpustat, i);

		total.cpustat[CPUTIME_USER] += cpustat[CPUTIME_USER];
		total.cpustat[CPUTIME_NICE] += cpustat[CPUTIME_NICE];
		total.cpustat[CPUTIME_SYSTEM] += cpustat[CPUTIME_SYSTEM];
		total.cpustat[CPUTIME_IDLE] += get_idle_time(kcpustat, i);
		total.cpustat[CPUTIME_IOWAIT] += get_iowait_time(kcpustat, i);// TODO: expose
		total.cpustat[CPUTIME_IRQ] += cpustat[CPUTIME_IRQ];
		total.cpustat[CPUTIME_SOFTIRQ] += cpustat[CPUTIME_SOFTIRQ];
		total.cpustat[CPUTIME_STEAL] += cpustat[CPUTIME_STEAL];
		total.cpustat[CPUTIME_GUEST] += cpustat[CPUTIME_GUEST];
		total.cpustat[CPUTIME_GUEST_NICE] += cpustat[CPUTIME_GUEST_NICE];
	}

	for (i = 0; i < mp->tp.nargs; i++) {
		struct trace_probe_arg *arg = mp->tp.args + i;

	}
}

static void trace_mprobe_monitor_work(struct wprk_struct *work);

static void trace_mprobe_monitor_func(struct trace_mprobe *mp,
				      struct trace_event_file *trace_file)
{
	struct mprobe_trace_entry_head *entry;
	struct trace_event_buffer fbuffer;
	struct trace_event_call *call = trace_probe_event_call(&mp->tp);

	if (WARN_ON_ONCE(call != trace_file->event_call))
		return;

	if (trace_trigger_soft_disabled(trace_file))
		return;

	entry = trace_event_buffer_reserve(&fbuffer, trace_file,
					   sizeof(*entry) + tf->tp.size);
	if (!entry)
		return;

	fbuffer.regs = NULL;
	entry = fbuffer.entry = ring_buffer_event_data(fbuffer.event);
	entry->ip = trace_mprobe_monitor_work;

	mp->monitor(mp, &entry[1]);

	trace_event_buffer_commit(&fbuffer);
}

static void trace_mprobe_monitor_work(struct wprk_struct *work)
{
	struct trace_mprobe *mp = container_of(work, struct trace_mprobe, work);
	struct event_file_link *link;

	guard(rcu)();
	trace_probe_for_each_link_rcu(link, &mp->tp)
		trace_mprobe_monitor_func(mp, link->file);

	// timer reset
}

static int trace_mprobe_create(const char *raw_command);
static int trace_mprobe_show(struct seq_file *m, struct dyn_event *ev);
static int trace_mprobe_release(struct dyn_event *ev);
static bool trace_mprobe_is_busy(struct dyn_event *ev);
static bool trace_mprobe_match(const char *system, const char *event,
			int argc, const char **argv, struct dyn_event *ev);

static struct dyn_event_operations trace_mprobe_ops = {
	.create = trace_mprobe_create,
	.show = trace_mprobe_show,
	.is_busy = trace_mprobe_is_busy,
	.free = trace_mprobe_release,
	.match = trace_mprobe_match,
};

static bool is_trace_mprobe(struct dyn_event *ev)
{
	return ev->ops == &trace_mprobe_ops;
}

static struct trace_mprobe *to_trace_mprobe(struct dyn_event *ev)
{
	return container_of(ev, struct trace_mprobe, devent);
}

#define for_each_trace_mprobe(pos, dpos)	\
	for_each_dyn_event(dpos)		\
		if (is_trace_mprobe(dpos) && (pos = to_trace_mprobe(dpos)))

unsigned long get_expire(struct trace_mprobe *mp)
{
	u64 next = mp->last + mp->interval;

	while (next < jiffies64) {
		next += mp->interval;
	}
	return next - jiffies64;
}

static struct trace_mprobe *find_trace_mprobe(const char *event,
					      const char *group)
{
	struct dyn_event *pos;
	struct trace_mprobe *mp;

	for_each_trace_mprobe(mp, pos)
		if (!strcmp(trace_probe_name(&mp->tp), event) &&
		    !strcmp(trace_probe_group_name(&mp->tp), group))
			return mp;
	return NULL;
}

static bool trace_mprobe_is_busy(struct dyn_event *ev)
{
	struct trace_mprobe *mp = to_trace_mprobe(ev);

	return trace_probe_is_enabled(&mp->tp);
}

static bool trace_mprobe_match(const char *system, const char *event,
			int argc, const char **argv, struct dyn_event *ev)
{
	struct trace_mprobe *mp = to_trace_mprobe(ev);

	return (event[0] == '\0' ||
		!strcmp(trace_probe_name(&mp->tp), event)) &&
		(!system || !strcmp(trace_probe_group_name(&mp->tp), system)) &&
		trace_probe_match_command_args(&mp->tp, argc, argv);
}

static void free_trace_mprobe(struct trace_mprobe *mp)
{
	if (mp) {
		trace_probe_cleanup(&mp->tp);
		kfree(mp);
	}
}

static struct trace_mprobe *alloc_trace_mprobe(const char *group,
						const char *event,
						unsigned long interval,
						int nargs)
{
	struct trace_mprobe *mp;
	int ret;

	mp = kzalloc(struct_size(mp, tp.args, nargs), GFP_KERNEL);
	if (!mp)
		return ERR_PTR(-ENOMEM);

	mp->interval = interval;
	ret = trace_probe_init(&mp->tp, event, group, false, nargs);
	if (ret < 0) {
		free_trace_mprobe(mp);
		return ERR_PTR(ret);
	}

	dyn_event_init(&mp->devent, &trace_mprobe_ops);
	return mp;
}

static int register_trace_mprobe(struct trace_mprobe *mp)
{
	struct trace_mprobe *old_mp;
	int ret = 0;

	mutex_lock(&event_mutex);

	old_mp = find_trace_mprobe(trace_probe_name(&mp->tp),
				trace_probe_group_name(&mp->tp));
	if (old_mp) {
		ret = -EEXIST;
		goto out;
	}

	dyn_event_add(&mp->devent, trace_probe_event_call(&mp->tp));
out:
	mutex_unlock(&event_mutex);
	return ret;
}

static int trace_mprobe_parse_arg(char *argv, ssize_t *size,
				  struct probe_arg *parg,
				  struct traceprobe_parse_context *ctx)
{

}

static int __trace_mprobe_create(int argc, const char *argv[])
{
	/*
	 * Add mprobe
	 *	m[:[GRP/]EVENT] INTERVAL [ARG=]MONARG [[ARG=]MONARG...]
	 *
	 * Monitor args:
	 *  stat.{user,nice,sys,idle,iowait,irq,sirq,steal,guest,gnice}
	 *  stat.{pgin,pgout,swin,swout}
	 *  stat.{intr,ctxt}
	 *  meminfo.{total,free,avail,buffer,cached,swapc,active}
	 *  meminfo.{swaptotal,swapfree,dirty,mapped,shmem}
	 */
	const char *event = NULL, group = MPROBE_EVENT_SYSTEM;
	struct trace_mprobe *mp = NULL;
	char gbuf[MAX_EVENT_NAME_LEN];
	unsigned long interval = 0;
	int i, ret;
	struct traceprobe_parse_context ctx = {
		.flags = TPARG_FL_MPROBE,
		.parse_arg = trace_mprobe_parse_arg,
	};

	if (argv[0][0] != 'm' || argc < 3)
		return -ECANCELED;

	trace_probe_log_init("trace_mprobe", argc, argv);

	if (kstrtoul(argv[1], 0, (unsigned long *)&interval) < 0) {
		trace_probe_log_set_index(1);
		trace_probe_log_err(0, BAD_INTERVAL);
		return -EINVAL;
	}

	event = strchr(&argv[0][1], ':');
	if (event) {
		event++;
		ret = traceprobe_parse_event_name(&event, &group, gbuf,
						  event - argv[0]);
		if (ret < 0)
			return ret;
	}

	argc -= 2; argv += 2;
	mp = alloc_trace_mprobe(group, event, interval, argc);
	if (!mp)
		return -ENOMEM;

	ctx.tp = &mp->tp;
	for (i = 0; i < argc && i < MAX_TRACE_ARGS; i++) {
		trace_probe_log_set_index(i + 2);
		ret = traceprobe_parse_probe_arg(&mp->tp, i, argv[i], &ctx);
		if (ret < 0) {
			free_trace_mprobe(mp);
			mp = NULL;
			break;
		}
	}

	ret = register_trace_mprobe(mp);
	if (ret) {
		trace_probe_log_set_index(0);
		trace_probe_log_err(0, EVENT_EXIST);
	}
	return ret;
}

static int trace_mprobe_create(const char *raw_command)
{
	return trace_probe_create(raw_command, __trace_mprobe_create);
}

static int trace_mprobe_release(struct dyn_event *ev)
{
	struct trace_mprobe *mp = to_trace_mprobe(ev);

	free_trace_mprobe(mp);
	return 0;
}

static int trace_mprobe_show(struct seq_file *m, struct dyn_event *ev)
{
	struct trace_mprobe *mp = to_trace_mprobe(ev);

	seq_printf(m, "m %lu", mp->interval);

	for (i = 0; i < tk->tp.nr_args; i++)
		seq_printf(m, " %s=%s", tk->tp.args[i].name, tk->tp.args[i].comm);
	seq_putc(m, '\n');
	return 0;
}