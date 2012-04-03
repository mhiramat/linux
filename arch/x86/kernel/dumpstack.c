/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002 Andi Kleen, SuSE Labs
 */
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/hardirq.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/ftrace.h>
#include <linux/kexec.h>
#include <linux/bug.h>
#include <linux/nmi.h>
#include <linux/sysfs.h>

#include <asm/stacktrace.h>
#include <asm/kprobes.h>
#include <asm/disasm.h>


int panic_on_unrecovered_nmi;
int panic_on_io_nmi;
unsigned int code_bytes = 64;
int kstack_depth_to_print = 3 * STACKSLOTS_PER_LINE;
static int die_counter;

void printk_address(unsigned long address, int reliable)
{
	printk(" [<%p>] %s%pB\n", (void *) address,
			reliable ? "" : "? ", (void *) address);
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
static void
print_ftrace_graph_addr(unsigned long addr, void *data,
			const struct stacktrace_ops *ops,
			struct thread_info *tinfo, int *graph)
{
	struct task_struct *task;
	unsigned long ret_addr;
	int index;

	if (addr != (unsigned long)return_to_handler)
		return;

	task = tinfo->task;
	index = task->curr_ret_stack;

	if (!task->ret_stack || index < *graph)
		return;

	index -= *graph;
	ret_addr = task->ret_stack[index].ret;

	ops->address(data, ret_addr, 1);

	(*graph)++;
}
#else
static inline void
print_ftrace_graph_addr(unsigned long addr, void *data,
			const struct stacktrace_ops *ops,
			struct thread_info *tinfo, int *graph)
{ }
#endif

/*
 * x86-64 can have up to three kernel stacks:
 * process stack
 * interrupt stack
 * severe exception (double fault, nmi, stack fault, debug, mce) hardware stack
 */

static inline int valid_stack_ptr(struct thread_info *tinfo,
			void *p, unsigned int size, void *end)
{
	void *t = tinfo;
	if (end) {
		if (p < end && p >= (end-THREAD_SIZE))
			return 1;
		else
			return 0;
	}
	return p > t && p < t + THREAD_SIZE - size;
}

unsigned long
print_context_stack(struct thread_info *tinfo,
		unsigned long *stack, unsigned long bp,
		const struct stacktrace_ops *ops, void *data,
		unsigned long *end, int *graph)
{
	struct stack_frame *frame = (struct stack_frame *)bp;

	while (valid_stack_ptr(tinfo, stack, sizeof(*stack), end)) {
		unsigned long addr;

		addr = *stack;
		if (__kernel_text_address(addr)) {
			if ((unsigned long) stack == bp + sizeof(long)) {
				ops->address(data, addr, 1);
				frame = frame->next_frame;
				bp = (unsigned long) frame;
			} else {
				ops->address(data, addr, 0);
			}
			print_ftrace_graph_addr(addr, data, ops, tinfo, graph);
		}
		stack++;
	}
	return bp;
}
EXPORT_SYMBOL_GPL(print_context_stack);

unsigned long
print_context_stack_bp(struct thread_info *tinfo,
		       unsigned long *stack, unsigned long bp,
		       const struct stacktrace_ops *ops, void *data,
		       unsigned long *end, int *graph)
{
	struct stack_frame *frame = (struct stack_frame *)bp;
	unsigned long *ret_addr = &frame->return_address;

	while (valid_stack_ptr(tinfo, ret_addr, sizeof(*ret_addr), end)) {
		unsigned long addr = *ret_addr;

		if (!__kernel_text_address(addr))
			break;

		ops->address(data, addr, 1);
		frame = frame->next_frame;
		ret_addr = &frame->return_address;
		print_ftrace_graph_addr(addr, data, ops, tinfo, graph);
	}

	return (unsigned long)frame;
}
EXPORT_SYMBOL_GPL(print_context_stack_bp);

static int print_trace_stack(void *data, char *name)
{
	printk("%s <%s> ", (char *)data, name);
	return 0;
}

/*
 * Print one address/symbol entries per line.
 */
static void print_trace_address(void *data, unsigned long addr, int reliable)
{
	touch_nmi_watchdog();
	printk(data);
	printk_address(addr, reliable);
}

static const struct stacktrace_ops print_trace_ops = {
	.stack			= print_trace_stack,
	.address		= print_trace_address,
	.walk_stack		= print_context_stack,
};

void
show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
		unsigned long *stack, unsigned long bp, char *log_lvl)
{
	printk("%sCall Trace:\n", log_lvl);
	dump_trace(task, regs, stack, bp, &print_trace_ops, log_lvl);
}

void show_trace(struct task_struct *task, struct pt_regs *regs,
		unsigned long *stack, unsigned long bp)
{
	show_trace_log_lvl(task, regs, stack, bp, "");
}

void show_stack(struct task_struct *task, unsigned long *sp)
{
	show_stack_log_lvl(task, NULL, sp, 0, "");
}

/*
 * The architecture-independent dump_stack generator
 */
void dump_stack(void)
{
	unsigned long bp;
	unsigned long stack;

	bp = stack_frame(current, NULL);
	printk("Pid: %d, comm: %.20s %s %s %.*s\n",
		current->pid, current->comm, print_tainted(),
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);
	show_trace(NULL, NULL, &stack, bp);
}
EXPORT_SYMBOL(dump_stack);

static arch_spinlock_t die_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int die_owner = -1;
static unsigned int die_nest_count;

unsigned __kprobes long oops_begin(void)
{
	int cpu;
	unsigned long flags;

	oops_enter();

	/* racy, but better than risking deadlock. */
	raw_local_irq_save(flags);
	cpu = smp_processor_id();
	if (!arch_spin_trylock(&die_lock)) {
		if (cpu == die_owner)
			/* nested oops. should stop eventually */;
		else
			arch_spin_lock(&die_lock);
	}
	die_nest_count++;
	die_owner = cpu;
	console_verbose();
	bust_spinlocks(1);
	return flags;
}
EXPORT_SYMBOL_GPL(oops_begin);

void __kprobes oops_end(unsigned long flags, struct pt_regs *regs, int signr)
{
	if (regs && kexec_should_crash(current))
		crash_kexec(regs);

	bust_spinlocks(0);
	die_owner = -1;
	add_taint(TAINT_DIE);
	die_nest_count--;
	if (!die_nest_count)
		/* Nest count reaches zero, release the lock. */
		arch_spin_unlock(&die_lock);
	raw_local_irq_restore(flags);
	oops_exit();

	if (!signr)
		return;
	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	do_exit(signr);
}

int __kprobes __die(const char *str, struct pt_regs *regs, long err)
{
#ifdef CONFIG_X86_32
	unsigned short ss;
	unsigned long sp;
#endif
	printk(KERN_DEFAULT
	       "%s: %04lx [#%d] ", str, err & 0xffff, ++die_counter);
#ifdef CONFIG_PREEMPT
	printk("PREEMPT ");
#endif
#ifdef CONFIG_SMP
	printk("SMP ");
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk("DEBUG_PAGEALLOC");
#endif
	printk("\n");
	if (notify_die(DIE_OOPS, str, regs, err,
			current->thread.trap_nr, SIGSEGV) == NOTIFY_STOP)
		return 1;

	show_registers(regs);
#ifdef CONFIG_X86_32
	if (user_mode_vm(regs)) {
		sp = regs->sp;
		ss = regs->ss & 0xffff;
	} else {
		sp = kernel_stack_pointer(regs);
		savesegment(ss, ss);
	}
	printk(KERN_EMERG "EIP: [<%08lx>] ", regs->ip);
	print_symbol("%s", regs->ip);
	printk(" SS:ESP %04x:%08lx\n", ss, sp);
#else
	/* Executive summary in case the oops scrolled away */
	printk(KERN_ALERT "RIP ");
	printk_address(regs->ip, 1);
	printk(" RSP <%016lx>\n", regs->sp);
#endif
	return 0;
}

#ifdef CONFIG_X86_DISASSEMBLER

/* Find the instruction boundary address */
static unsigned long find_instruction_boundary(unsigned long saddr,
						unsigned long *poffs,
						char **modname, char *namebuf)
{
	kprobe_opcode_t buf[MAX_INSN_SIZE];
	unsigned long offs, addr, fixed;
	struct insn insn;

	/* find which function has given ip */
	if (!kallsyms_lookup(saddr, NULL, &offs, modname, namebuf))
		return 0;

	addr = saddr - offs;	/* Function start address */
	while (addr < saddr) {
		fixed = recover_probed_instruction(buf, addr);
		kernel_insn_init(&insn, (void *)fixed);
		insn_get_length(&insn);
		addr += insn.length;
	}
	if (poffs)
		*poffs = offs;

	return addr;
}

static int disasm_printk(unsigned long addr, unsigned long *next,
			 unsigned long ip)
{
	char buf[DISASM_STR_LEN];
	u8 kbuf[MAX_INSN_SIZE];
	struct insn insn;
	unsigned long fixed;
	int i, ret;
	u8 *v = (u8 *)addr;

	/* recover if the instruction is probed */
	fixed = recover_probed_instruction(kbuf, addr);
	kernel_insn_init(&insn, (void *)fixed);
	insn_get_length(&insn);
	insn.kaddr = (void *)addr;

	printk(KERN_CONT "%p: ", v);
	for (i = 0; i < MAX_INSN_SIZE / 2 && i < insn.length; i++)
		printk(KERN_CONT "%02x ", ((u8 *)v)[i]);
	if (i != MAX_INSN_SIZE / 2)
		printk(KERN_CONT "%*s", 3 * (MAX_INSN_SIZE / 2 - i), " ");

	/* print assembly code */
	ret = disassemble(buf, DISASM_STR_LEN, &insn, DISASM_SYNTAX_ATT);
	if (ret < 0)
		return ret;
	printk(KERN_CONT "%s%s%s\n", (fixed != addr) ? "(probed)" : "", buf,
		(addr == ip) ? "\t<-- trapping instruction" : "");

	if (i < insn.length) {
		printk(KERN_CONT "%p: ", v + i);
		for (; i < insn.length - 1; i++)
			printk(KERN_CONT "%02x ", ((u8 *)v)[i]);
		printk(KERN_CONT "%02x\n", ((u8 *)v)[i]);
	}

	if (next)
		*next = addr + insn.length;

	return 0;
}

/* Disassemble between (ip - prologue) to (ip - prologue + length) */
static int disassemble_code_dump(unsigned long ip, unsigned long prologue,
				 unsigned long length)
{
	unsigned long offs;
	unsigned long addr = ip - prologue;
	unsigned long eaddr = ip - prologue + length;
	char buf[KSYM_NAME_LEN] = {0};
	char *modname;

	/* given address must be in text area */
	if (!kernel_text_address(addr) || !kernel_text_address(eaddr))
		return -EINVAL;

	addr = find_instruction_boundary(addr, &offs, &modname, buf);
	if (!addr)
		return -EINVAL;

	if (modname)
		printk(KERN_CONT "\n<%s+0x%lx [%s]>:\n", buf,
			addr - (ip - offs), modname);
	else
		printk(KERN_CONT "\n<%s+0x%lx>:\n", buf, addr - (ip - offs));

	do {
		if (disasm_printk(addr, &addr, ip) < 0)
			break;
	} while (addr < eaddr);

	return 0;
}
#else
static int disassemble_code_dump(unsigned long ip, unsigned long prologue,
				 unsigned long length)
{
	return -ENOTSUPP;
}
#endif

void __kprobes show_code_dump(struct pt_regs *regs)
{
	int i;
	unsigned int code_prologue = code_bytes * 43 / 64;
	unsigned int code_len = code_bytes;
	unsigned char c;
	u8 *ip;

	/* try to disassemble code */
	if (disassemble_code_dump(regs->ip, code_prologue, code_len) == 0)
		return;

	ip = (u8 *)regs->ip - code_prologue;
	if (ip < (u8 *)PAGE_OFFSET || probe_kernel_address(ip, c)) {
		/* try starting at IP */
		ip = (u8 *)regs->ip;
		code_len = code_len - code_prologue + 1;
	}
	for (i = 0; i < code_len; i++, ip++) {
		if (ip < (u8 *)PAGE_OFFSET ||
				probe_kernel_address(ip, c)) {
#ifdef CONFIG_X86_32
			printk(KERN_CONT " Bad EIP value.");
#else
			printk(KERN_CONT " Bad RIP value.");
#endif
			break;
		}
		if (ip == (u8 *)regs->ip)
			printk(KERN_CONT "<%02x> ", c);
		else
			printk(KERN_CONT "%02x ", c);
	}
}

/*
 * This is gone through when something in the kernel has done something bad
 * and is about to be terminated:
 */
void die(const char *str, struct pt_regs *regs, long err)
{
	unsigned long flags = oops_begin();
	int sig = SIGSEGV;

	if (!user_mode_vm(regs))
		report_bug(regs->ip, regs);

	if (__die(str, regs, err))
		sig = 0;
	oops_end(flags, regs, sig);
}

static int __init kstack_setup(char *s)
{
	if (!s)
		return -EINVAL;
	kstack_depth_to_print = simple_strtoul(s, NULL, 0);
	return 0;
}
early_param("kstack", kstack_setup);

static int __init code_bytes_setup(char *s)
{
	code_bytes = simple_strtoul(s, NULL, 0);
	if (code_bytes > 8192)
		code_bytes = 8192;

	return 1;
}
__setup("code_bytes=", code_bytes_setup);
