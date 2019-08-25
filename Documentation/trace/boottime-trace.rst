.. SPDX-License-Identifier: GPL-2.0

=================
Boot-time tracing
=================

:Author: Masami Hiramatsu <mhiramat@kernel.org>

Overview
========

Boot-time tracing allows users to trace boot-time process including
device initialization with full features of ftrace including per-event
filter and actions, histograms, kprobe-events and synthetic-events,
and trace instances.
Since kernel cmdline is not enough to control these complex features,
this uses supplemental kernel cmdline (SKC) to describe tracing
feature programming.

Options in Supplemental Kernel Cmdline
======================================

Here is the list of available options list for boot time tracing in
supplemental kenrel cmdline file [1]_. All options are under "ftrace."
prefix to isolate from other subsystems.

.. [1] See Documentation/admin-guide/skc.rst for details.

Ftrace Global Options
---------------------

These options are only for global ftrace node since these are globally
applied.

ftrace.tp_printk;
   Output trace-event data on printk buffer too.

ftrace.dump_on_oops [= MODE];
   Dump ftrace on Oops. If MODE = 1 or omitted, dump trace buffer
   on all CPUs. If MODE = 2, dump a buffer on a CPU which kicks Oops.

ftrace.traceoff_on_warning;
   Stop tracing if WARN_ON() occurs.

ftrace.fgraph.filters = FILTER[, FILTER2...];
   Add fgraph tracing function filters.

ftrace.fgraph.notraces = FILTER[, FILTER2...];
   Add fgraph non tracing function filters.

ftrace.fgraph.max_depth = MAX_DEPTH;
   Set MAX_DEPTH to maximum depth of fgraph tracer.


Ftrace Per-instance Options
---------------------------

These options can be used for each instance including global ftrace node.

ftrace.[instance.INSTANCE.]options = OPT1[, OPT2[...]];
   Enable given ftrace options.

ftrace.[instance.INSTANCE.]trace_clock = CLOCK;
   Set given CLOCK to ftrace's trace_clock.

ftrace.[instance.INSTANCE.]buffer_size = SIZE;
   Configure ftrace buffer size to SIZE. You can use "KB" or "MB"
   for that SIZE.

ftrace.[instance.INSTANCE.]alloc_snapshot;
   Allocate snapshot buffer.

ftrace.[instance.INSTANCE.]events = EVENT[, EVENT2[...]];
   Enable given events on boot. You can use a wild card in EVENT.

ftrace.[instance.INSTANCE.]tracer = TRACER;
   Set TRACER to current tracer on boot. (e.g. function)

ftrace.[instance.INSTANCE.]ftrace.filters
   This will take an array of tracing function filter rules

ftrace.[instance.INSTANCE.]ftrace.notraces
   This will take an array of NON-tracing function filter rules


Ftrace Per-Event Options
------------------------

These options are setting per-event options.

ftrace.[instance.INSTANCE.]event.GROUP.EVENT.enable;
   Enables GROUP:EVENT tracing.

ftrace.[instance.INSTANCE.]event.GROUP.EVENT.filter = FILTER;
   Set FILTER rule to the GROUP:EVENT.

ftrace.[instance.INSTANCE.]event.GROUP.EVENT.actions = ACTION[, ACTION2[...]];
   Set ACTIONs to the GROUP:EVENT.

ftrace.[instance.INSTANCE.]event.kprobes.EVENT.probes = PROBE[, PROBE2[...]];
   Defines new kprobe event based on PROBEs. It is able to define
   multiple probes on one event, but those must have same type of
   arguments. This option is available only for the event which
   group name is "kprobes".

ftrace.[instance.INSTANCE.]event.synthetic.EVENT.fields = FIELD[, FIELD2[...]];
   Defines new synthetic event with FIELDs. Each field should be
   "type varname".

Note that kprobe and synthetic event definitions can be written under
instance node, but those are also visible from other instances. So please
take care for event name conflict.

Examples
========

For example, to add filter and actions for each event, define kprobe
events, and synthetic events with histogram, write SKC like below.

::

  ftrace.event {
        task.task_newtask {
                filter = "pid < 128";
                enable;
        }
        kprobes.vfs_read {
                probes = "vfs_read $arg1 $arg2";
                filter = "common_pid < 200";
                enable;
        }
        synthetic.initcall_latency {
                fields = "unsigned long func", "u64 lat";
                actions = "hist:keys=func.sym,lat:vals=lat:sort=lat";
        }
        initcall.initcall_start {
                actions = "hist:keys=func:ts0=common_timestamp.usecs";
        }
        initcall.initcall_finish {
                actions = "hist:keys=func:lat=common_timestamp.usecs-$ts0:onmatch(initcall.initcall_start).initcall_latency(func,$lat)";
        }
  }

Also, boottime tracing supports "instance" node, which allows us to run
several tracers for different purpose at once. For example, one tracer
is for tracing functions in module alpha, and others tracing module beta,
you can write as below.

::

  ftrace.instance {
        foo {
                tracer = "function";
                ftrace-filters = "*:mod:alpha";
        }
        bar {
                tracer = "function";
                ftrace-filters = "*:mod:beta";
        }
  }

The instance node also accepts event nodes so that each instance
can customize its event tracing.

This boot-time trace also supports ftrace kernel parameters.
For example, following kernel parameters

::

 trace_options=sym-addr trace_event=initcall:* tp_printk trace_buf_size=1M ftrace=function ftrace_filter="vfs*"

This can be written in SKC like below.

::

  ftrace {
        options = sym-addr;
        events = "initcall:*";
        tp-printk;
        buffer-size = 1MB;
        ftrace-filters = "vfs*";
  }

However, since the initialization timing is different, if you need
to trace very early boot, please use normal kernel parameters.
