/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUNG_TASK_H
#define _LINUX_HUNG_TASK_H

#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/sysctl.h>

#ifdef CONFIG_DETECT_HUNG_TASK
/* Call where a lock is acquired. */
static inline void hung_task_acquire_lock(void *lock_addr)
{
	/* The lock must be a mutex or any sleepable lock. So ignore interrupts. */
	if (!current->first_lock_addr) {
		current->first_lock_addr = (unsigned long)lock_addr;
		current->first_lock_time = jiffies;
	}
}

/* Call where a lock is released. */
static inline void hung_task_release_lock(void *lock_addr)
{
	if (current->first_lock_addr == (unsigned long)lock_addr) {
		current->first_lock_addr = 0;
		current->first_lock_time = 0;
	}
}

/* Return current timeout budget for hung_task for blocked tasks. */
static inline unsigned long hung_task_timeout_budget()
{
	unsigned long timeout = sysctl_hung_task_timeout_secs * HZ;

	if (!current->first_lock_addr || !timeout)
		return ULONG_MAX;

	if (time_after_eq(jiffies, current->first_lock_time + timeout))
		return 0;

	return current->first_lock_time + timeout - jiffies;
}

#else
static inline void hung_task_acquire_lock(void *lock_addr __maybe_unused)
{
}

static inline void hung_task_release_lock(void *lock_addr __maybe_unused)
{
}

#define hung_task_timeout_budget()	(ULONG_MAX)
#endif

#endif