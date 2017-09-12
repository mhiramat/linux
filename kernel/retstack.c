/*
 * retstack.c: Per-thread return stack
 *
 * Copied from kernel/trace/ftrace.c and kernel/trace/trace_functions_graph.c
 */
#include <linux/retstack.h>
#include <linux/ftrace.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

static int retstack_active;
static bool retstack_killed;

/**
 * retstack_is_dead - returns true if retstack_kill() was called
 *
 * retstack_kill() is called when a severe error is detected in
 * the return stack operation. This function is called by the critical
 * paths of function graph to keep those paths from doing any more harm.
 */
bool retstack_is_dead(void)
{
	return retstack_killed;
}

/**
 * retstack_kill - set to permanently disable return stack operation
 *
 * In case of an error in return stack operation, this is called
 * to try to keep return stack user from causing any more harm.
 * Usually this is pretty severe and this is called to try to at least
 * get a warning out to the user.
 */
void retstack_kill(void)
{
	retstack_killed = true;
}

static struct retstack *retstack_alloc(void)
{
	return kzalloc(RETSTACK_MAX_DEPTH * sizeof(struct ftrace_ret_stack),
			GFP_KERNEL);
}

/* Try to assign a return stack array on RETSTACK_ALLOC_SIZE tasks. */
static int retstack_init_tasklist(void)
{
	int i;
	int ret = 0;
	int start = 0, end = RETSTACK_ALLOC_SIZE;
	struct task_struct *g, *t;
	struct retstack *ret_stack_list[RETSTACK_ALLOC_SIZE];

	for (i = 0; i < RETSTACK_ALLOC_SIZE; i++) {
		ret_stack_list[i] = retstack_alloc();
		if (!ret_stack_list[i]) {
			start = 0;
			end = i;
			ret = -ENOMEM;
			goto free;
		}
	}

	read_lock(&tasklist_lock);
	do_each_thread(g, t) {
		if (start == end) {
			ret = -EAGAIN;
			goto unlock;
		}

		if (t->ret_stack == NULL) {
			atomic_set(&t->tracing_graph_pause, 0);
			atomic_set(&t->trace_overrun, 0);
			t->curr_ret_stack = -1;
			/* Make sure the tasks see the -1 first: */
			smp_wmb();
			t->ret_stack = ret_stack_list[start++];
		}
	} while_each_thread(g, t);

unlock:
	read_unlock(&tasklist_lock);
free:
	for (i = start; i < end; i++)
		kfree(ret_stack_list[i]);
	return ret;
}

/* Allocate a return stack for each task */
int retstack_init(void)
{
	int ret, cpu;

	if (retstack_active++)
		return 0;

	/* The cpu_boot init_task->ret_stack will never be freed */
	for_each_online_cpu(cpu) {
		if (!idle_task(cpu)->ret_stack)
			retstack_init_idle(idle_task(cpu), cpu);
	}

	do {
		ret = retstack_init_tasklist();
	} while (ret == -EAGAIN);

	return ret;
}

int retstack_exit(void)
{
	retstack_active--;
	WARN_ON(retstack_active < 0);
}

static DEFINE_PER_CPU(struct retstack *, idle_ret_stack);

static void
__retstack_init_task(struct task_struct *t, struct retstack *ret_stack)
{
	atomic_set(&t->tracing_graph_pause, 0);
	atomic_set(&t->trace_overrun, 0);
	t->ftrace_timestamp = 0;
	/* make curr_ret_stack visible before we add the ret_stack */
	smp_wmb();
	t->ret_stack = ret_stack;
}

/*
 * Allocate a return stack for the idle task. May be the first
 * time through, or it may be done by CPU hotplug online.
 */
void retstack_init_idle(struct task_struct *t, int cpu)
{
	t->curr_ret_stack = -1;
	/*
	 * The idle task has no parent, it either has its own
	 * stack or no stack at all.
	 */
	if (t->ret_stack)
		WARN_ON(t->ret_stack != per_cpu(idle_ret_stack, cpu));

	if (retstack_active) {
		struct retstack *ret_stack;

		ret_stack = per_cpu(idle_ret_stack, cpu);
		if (!ret_stack) {
			ret_stack = retstack_alloc();
			if (!ret_stack)
				return;
			per_cpu(idle_ret_stack, cpu) = ret_stack;
		}
		__retstack_init_task(t, ret_stack);
	}
}

/* Allocate a return stack for newly created task */
void retstack_init_task(struct task_struct *t)
{
	/* Make sure we do not use the parent ret_stack */
	t->ret_stack = NULL;
	t->curr_ret_stack = -1;

	if (retstack_active) {
		struct retstack *ret_stack;

		ret_stack = retstack_alloc();
		if (!ret_stack)
			return;
		__retstack_init_task(t, ret_stack);
	}
}

void retstack_exit_task(struct task_struct *t)
{
	struct retstack	*ret_stack = t->ret_stack;

	t->ret_stack = NULL;
	/* NULL must become visible to IRQs before we free it: */
	barrier();

	kfree(ret_stack);
}

int
retstack_push(unsigned long ret, unsigned long func, unsigned long *retp,
	      struct retstack **entry)
{
	unsigned long long calltime;
	int index;

	if (unlikely(retstack_is_dead()))
		return -EBUSY;

	if (!current->ret_stack)
		return -EBUSY;

	/*
	 * We must make sure the ret_stack is tested before we read
	 * anything else.
	 */
	smp_rmb();

	/* The return trace stack is full */
	if (current->curr_ret_stack == RETSTACK_MAX_DEPTH - 1) {
		atomic_inc(&current->trace_overrun);
		return -EBUSY;
	}

	/*
	 * The curr_ret_stack is initialized to -1 and get increased
	 * in this function.  So it can be less than -1 only if there
	 * is a bug.
	 */
	if (current->curr_ret_stack < -1)
		return -EBUSY;
	index = ++current->curr_ret_stack;
	barrier();

	current->ret_stack[index].ret = ret;
	current->ret_stack[index].func = func;
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
	current->ret_stack[index].retp = retp;
#endif
	*entry = &current->ret_stack[index];
	return 0;
}

int retstack_peek(struct retstack **entry)
{
	int index;

	index = current->curr_ret_stack;

	if (unlikely(index < 0 || index >= RETSTACK_MAX_DEPTH))
		return -EINVAL;

	*entry = &current->ret_stack[index];

	return 0;
}

int retstack_pop(unsigned long *ret, unsigned long *func)
{
	int index;

	index = current->curr_ret_stack;

	if (unlikely(index < 0 || index >= RETSTACK_MAX_DEPTH)) {
		retstack_kill();
		WARN_ON(1);
		return -EINVAL;
	}
	*ret = current->ret_stack[index].ret;
	*func = current->ret_stack[index].func;
	barrier();
	current->curr_ret_stack--;

	return 0;
}

/**
 * retstack_ret_addr - convert a potentially modified stack return address
 *			to its original value
 *
 * This function can be called by stack unwinding code to convert a found stack
 * return address ('ret') to its original value, in case the function graph
 * tracer has modified it to be 'return_to_handler'.  If the address hasn't
 * been modified, the unchanged value of 'ret' is returned.
 *
 * 'idx' is a state variable which should be initialized by the caller to zero
 * before the first call.
 *
 * 'retp' is a pointer to the return address on the stack.  It's ignored if
 * the arch doesn't have HAVE_FUNCTION_GRAPH_RET_ADDR_PTR defined.
 */
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
unsigned long retstack_ret_addr(struct task_struct *task, int *idx,
				unsigned long ret, unsigned long *retp)
{
	int index = task->curr_ret_stack;
	int i;

	if (!in_return_text(ret))
		return ret;

	if (index < 0)
		return ret;

	for (i = 0; i <= index; i++)
		if (task->ret_stack[i].retp == retp)
			return task->ret_stack[i].ret;

	return ret;
}
#else /* !HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */
unsigned long retstack_ret_addr(struct task_struct *task, int *idx,
				unsigned long ret, unsigned long *retp)
{
	int task_idx;

	if (!in_return_text(ret))
		return ret;

	task_idx = task->curr_ret_stack;

	if (!task->ret_stack || task_idx < *idx)
		return ret;

	task_idx -= *idx;
	(*idx)++;

	return task->ret_stack[task_idx].ret;
}
#endif /* HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */

