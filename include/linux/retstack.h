#ifndef _LINUX_RETSTACK_H
#define _LINUX_RETSTACK_H

/*
 * Extra return stack for function return hook
 */

#define RETSTACK_ALLOC_SIZE 32
#define RETSTACK_MAX_DEPTH 50

void retstack_abort(void);
bool retstack_is_dead(void);

int retstack_init(void);
int retstack_exit(void);
void retstack_init_idle(struct task_struct *t, int cpu);
void retstack_init_task(struct task_struct *t);
void retstack_exit_task(struct task_struct *t);

int retstack_push(unsigned long ret, unsigned long func, unsigned long *retp,
		  struct retstack **entry);
int retstack_peek(struct retstack **entry);
int retstack_pop(unsigned long *ret, unsigned long *func);
unsigned long retstack_ret_addr(struct task_struct *task, int *idx,
				unsigned long ret, unsigned long *retp);

#endif
