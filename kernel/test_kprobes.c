/*
 * test_kprobes.c - simple sanity test for *probes
 *
 * Copyright IBM Corp. 2008
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 * the GNU General Public License for more details.
 */

#define pr_fmt(fmt) "Kprobe smoke test: " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/random.h>

#define div_factor 3

static u32 rand1, preh_val, posth_val, jph_val, nest_val;
static int errors, handler_errors, num_tests;
static u32 (*target)(u32 value);
static u32 (*target2)(u32 value);

static noinline u32 kprobe_target(u32 value)
{
	pr_err("target function called\n");
	return (value / div_factor);
}

static int kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	if (preemptible()) {
		handler_errors++;
		pr_err("pre-handler is preemptible\n");
	}
	if (preh_val == 0) {
		pr_err("Normal pre handler called");
		preh_val = (rand1 / div_factor);
		target(rand1);
	} else {
		pr_err("Nested pre handler called");
		nest_val++;
	}

	return 0;
}

static void kp_post_handler(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	if (preemptible()) {
		handler_errors++;
		pr_err("post-handler is preemptible\n");
	}
	if (preh_val != (rand1 / div_factor)) {
		handler_errors++;
		pr_err("incorrect value in post_handler\n");
	}
	posth_val = preh_val + div_factor;
}

static struct kprobe kp = {
	.symbol_name = "kprobe_target",
	.pre_handler = kp_pre_handler,
	.post_handler = kp_post_handler
};

static void report_kprobe(struct kprobe *p)
{
	struct kprobe *pp;
        preempt_disable();
	pp = get_kprobe(p->addr);
	preempt_enable();

	pr_err("DEBUG: kprobe at %pF %s%s%s%s\n", p->addr,
                (kprobe_gone(p) ? "[GONE]" : ""),
                ((kprobe_disabled(p) && !kprobe_gone(p)) ?  "[DISABLED]" : ""),
                (kprobe_optimized(pp) ? "[OPTIMIZED]" : ""),
                (kprobe_ftrace(pp) ? "[FTRACE]" : ""));
}

static int test_kprobe(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe returned %d\n", ret);
		return ret;
	}
	report_kprobe(&kp);

	ret = target(rand1);
	unregister_kprobe(&kp);

	if (preh_val == 0) {
		pr_err("kprobe pre_handler not called\n");
		handler_errors++;
	}

	if (posth_val == 0) {
		pr_err("kprobe post_handler not called\n");
		handler_errors++;
	}

#ifdef CONFIG_HAVE_NESTED_KPROBES
	if (kp.nmissed || nest_val == 0) {
		pr_err("kprobe nested in pre_handler not called\n");
		handler_errors++;
	}
#endif

	return 0;
}

static noinline u32 kprobe_target2(u32 value)
{
	return (value / div_factor) + 1;
}

static int kp_pre_handler2(struct kprobe *p, struct pt_regs *regs)
{
	preh_val = (rand1 / div_factor) + 1;
	return 0;
}

static void kp_post_handler2(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	if (preh_val != (rand1 / div_factor) + 1) {
		handler_errors++;
		pr_err("incorrect value in post_handler2\n");
	}
	if (posth_val == 0) {
		pr_err("Normal post handler called");
		posth_val = preh_val + div_factor;
		target2(rand1);
	} else {
		pr_err("Nested post handler called");
		nest_val++;
	}
}

static struct kprobe kp2 = {
	.symbol_name = "kprobe_target2",
	.pre_handler = kp_pre_handler2,
	.post_handler = kp_post_handler2
};

static int test_kprobes(void)
{
	int ret;
	struct kprobe *kps[2] = {&kp, &kp2};

	/* addr and flags should be cleard for reusing kprobe. */
	kp.addr = NULL;
	kp.flags = 0;
	ret = register_kprobes(kps, 2);
	if (ret < 0) {
		pr_err("register_kprobes returned %d\n", ret);
		return ret;
	}

	preh_val = 0;
	posth_val = 0;
	nest_val = 0;
	ret = target(rand1);

	report_kprobe(&kp);
	report_kprobe(&kp2);
	if (preh_val == 0) {
		pr_err("kprobe pre_handler not called\n");
		handler_errors++;
	}

	if (posth_val == 0) {
		pr_err("kprobe post_handler not called\n");
		handler_errors++;
	}

	preh_val = 0;
	posth_val = 0;
	ret = target2(rand1);

	if (preh_val == 0) {
		pr_err("kprobe pre_handler2 not called\n");
		handler_errors++;
	}

	if (posth_val == 0) {
		pr_err("kprobe post_handler2 not called\n");
		handler_errors++;
	}

#ifdef CONFIG_HAVE_NESTED_KPROBES
	if (kp2.nmissed || nest_val == 0) {
		pr_err("kprobe nested in post_handler not called\n");
		handler_errors++;
	}
#endif
	unregister_kprobes(kps, 2);
	return 0;

}

static u32 j_kprobe_target(u32 value)
{
	if (preemptible()) {
		handler_errors++;
		pr_err("jprobe-handler is preemptible\n");
	}
	if (value != rand1) {
		handler_errors++;
		pr_err("incorrect value in jprobe handler\n");
	}

	if (jph_val == 0) {
		jph_val = rand1;
#ifdef CONFIG_HAVE_NESTED_KPROBES
		target(rand1);
	} else {
		nest_val++;
#endif
	}
	jprobe_return();
	return 0;
}

static struct jprobe jp = {
	.entry		= j_kprobe_target,
	.kp.symbol_name = "kprobe_target"
};

static int test_jprobe(void)
{
	int ret;

	nest_val = 0;
	ret = register_jprobe(&jp);
	if (ret < 0) {
		pr_err("register_jprobe returned %d\n", ret);
		return ret;
	}

	ret = target(rand1);
	unregister_jprobe(&jp);
	if (jph_val == 0) {
		pr_err("jprobe handler not called\n");
		handler_errors++;
	}

#ifdef CONFIG_HAVE_NESTED_KPROBES
	if (jp.kp.nmissed || nest_val == 0) {
		pr_err("jprobe nested in entry handler not called\n");
		handler_errors++;
	}
#endif
	return 0;
}

static struct jprobe jp2 = {
	.entry          = j_kprobe_target,
	.kp.symbol_name = "kprobe_target2"
};

static int test_jprobes(void)
{
	int ret;
	struct jprobe *jps[2] = {&jp, &jp2};

	/* addr and flags should be cleard for reusing kprobe. */
	jp.kp.addr = NULL;
	jp.kp.flags = 0;
	jp.kp.nmissed = 0;
	nest_val = 0;
	ret = register_jprobes(jps, 2);
	if (ret < 0) {
		pr_err("register_jprobes returned %d\n", ret);
		return ret;
	}

	jph_val = 0;
	ret = target(rand1);
	if (jph_val == 0) {
		pr_err("jprobe handler not called\n");
		handler_errors++;
	}

	jph_val = 0;
	ret = target2(rand1);
	if (jph_val == 0) {
		pr_err("jprobe handler2 not called\n");
		handler_errors++;
	}
	unregister_jprobes(jps, 2);

#ifdef CONFIG_HAVE_NESTED_KPROBES
	/* Note that only jp is nested in both case */
	if (jp.kp.nmissed || nest_val == 0) {
		pr_err("jprobe nested in entry handler not called(2)\n");
		handler_errors++;
	}
#endif
	return 0;
}
#ifdef CONFIG_KRETPROBES
static u32 krph_val;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (preemptible()) {
		handler_errors++;
		pr_err("kretprobe entry handler is preemptible\n");
	}
	krph_val = (rand1 / div_factor);
	return 0;
}

static int return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long ret = regs_return_value(regs);

#if 0
	if (jph_val == 0) {
		jph_val = rand1;
		target(rand1);
	} else
		nest_val++;
#endif

	if (preemptible()) {
		handler_errors++;
		pr_err("kretprobe return handler is preemptible\n");
	}
	if (ret != (rand1 / div_factor)) {
		handler_errors++;
		pr_err("incorrect value in kretprobe handler\n");
	}
	if (krph_val == 0) {
		handler_errors++;
		pr_err("call to kretprobe entry handler failed\n");
	}

	krph_val = rand1;
	return 0;
}

static struct kretprobe rp = {
	.handler	= return_handler,
	.entry_handler  = entry_handler,
	.kp.symbol_name = "kprobe_target"
};

static int test_kretprobe(void)
{
	int ret;

	jph_val = 0;
	nest_val = 0;
	ret = register_kretprobe(&rp);
	if (ret < 0) {
		pr_err("register_kretprobe returned %d\n", ret);
		return ret;
	}

	ret = target(rand1);
	unregister_kretprobe(&rp);
	if (krph_val != rand1) {
		pr_err("kretprobe handler not called\n");
		handler_errors++;
	}

#ifdef CONFIG_HAVE_NESTED_KPROBES
	if (rp.kp.nmissed || nest_val == 0) {
		pr_err("kretprobe nested in return handler not called\n");
		handler_errors++;
	}
#endif
	return 0;
}

static int return_handler2(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long ret = regs_return_value(regs);

	if (ret != (rand1 / div_factor) + 1) {
		handler_errors++;
		pr_err("incorrect value in kretprobe handler2\n");
	}
	if (krph_val == 0) {
		handler_errors++;
		pr_err("call to kretprobe entry handler failed\n");
	}

	krph_val = rand1;
	return 0;
}

static struct kretprobe rp2 = {
	.handler	= return_handler2,
	.entry_handler  = entry_handler,
	.kp.symbol_name = "kprobe_target2"
};

static int test_kretprobes(void)
{
	int ret;
	struct kretprobe *rps[2] = {&rp, &rp2};

	/* addr and flags should be cleard for reusing kprobe. */
	rp.kp.addr = NULL;
	rp.kp.flags = 0;
	ret = register_kretprobes(rps, 2);
	if (ret < 0) {
		pr_err("register_kretprobe returned %d\n", ret);
		return ret;
	}

	krph_val = 0;
	ret = target(rand1);
	if (krph_val != rand1) {
		pr_err("kretprobe handler not called\n");
		handler_errors++;
	}

	krph_val = 0;
	ret = target2(rand1);
	if (krph_val != rand1) {
		pr_err("kretprobe handler2 not called\n");
		handler_errors++;
	}
	unregister_kretprobes(rps, 2);
	return 0;
}
#endif /* CONFIG_KRETPROBES */

int init_test_probes(void)
{
	int ret;

	target = kprobe_target;
	target2 = kprobe_target2;

	do {
		rand1 = prandom_u32();
	} while (rand1 <= div_factor);

	pr_info("started\n");
	num_tests++;
	ret = test_kprobe();
	if (ret < 0)
		errors++;

	num_tests++;
	ret = test_kprobes();
	if (ret < 0)
		errors++;

	num_tests++;
	ret = test_jprobe();
	if (ret < 0)
		errors++;

	num_tests++;
	ret = test_jprobes();
	if (ret < 0)
		errors++;

#ifdef CONFIG_KRETPROBES
	num_tests++;
	ret = test_kretprobe();
	if (ret < 0)
		errors++;

	num_tests++;
	ret = test_kretprobes();
	if (ret < 0)
		errors++;
#endif /* CONFIG_KRETPROBES */

	if (errors)
		pr_err("BUG: %d out of %d tests failed\n", errors, num_tests);
	else if (handler_errors)
		pr_err("BUG: %d error(s) running handlers\n", handler_errors);
	else
		pr_info("passed successfully\n");

	return 0;
}
