/*
 * Copyright (C) 2017 Thomas Gleixner <tglx@linutronix.de>
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/bitmap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/irq.h>

enum {
	MATRIX_ALLOC = 0,
	MATRIX_RESERVE,
	MATRIX_RESERVE_INALLOC,
	MATRIX_MAX_COUNTERS,
};

struct cpumap {
	unsigned int		counters[MATRIX_MAX_COUNTERS];
	unsigned long		map[0];
};

struct irq_matrix {
	unsigned int		maxirqs;
	unsigned int		alloc_start;
	unsigned int		alloc_end;
	struct cpumap __percpu	*maps;
};

/**
 * irq_alloc_matrix - Allocate a irq_matrix structure and initialize it
 * @maxirqs:		The maximum number of interrupts per CPU
 * @alloc_start:	From which bit the allocation search starts
 * @alloc_end:		At which bit the allocation search ends, i.e first
 *			invalid bit
 */
__init struct irq_matrix *irq_alloc_matrix(unsigned int maxirqs,
					   unsigned int alloc_start,
					   unsigned int alloc_end)
{
	int mapsize = BITS_TO_LONGS(maxirqs) * sizeof(unsigned long);
	struct irq_matrix *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return NULL;

	m->maxirqs = maxirqs;
	m->alloc_start = alloc_start;
	m->alloc_end = alloc_end;
	m->maps = __alloc_percpu(mapsize + sizeof(struct cpumap),
				 __alignof__(struct cpumap));
	if (!m->maps) {
		kfree(m);
		return NULL;
	}
	return m;
}

/**
 * irq_matrix_reset - Reset interrupts in the matrix
 * @m:		Pointer to the matrix which needs to be updated
 * @msk:	Which CPU maps need be updated
 */
void irq_matrix_reset(struct irq_matrix *m, const struct cpumask *msk)
{
	unsigned int cpu;

	for_each_cpu(cpu, msk) {
		struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

		bitmap_zero(cm->map, m->maxirqs);
		memset(cm->counters, 0, sizeof(cm->counters));
	}
}

static void irq_matrix_set(struct irq_matrix *m, const struct cpumask *msk,
			   unsigned int start, unsigned int num, int which)
{
	unsigned int cpu;

	for_each_cpu(cpu, msk) {
		struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

		bitmap_set(cm->map, start, num);
		cm->counters[which] += num;
	}
}

/**
 * irq_matrix_reserve - Reserve interrupts in the matrix
 * @m:		Pointer to the matrix which needs to be updated
 * @msk:	Which CPU maps need be updated
 * @start:	Start of the bitarea to reserve
 * @num:	Number of bits to reserve
 */
int irq_matrix_reserve(struct irq_matrix *m, const struct cpumask *msk,
		       unsigned int start, unsigned int num)
{
	int which = MATRIX_RESERVE;

	if (!num || start + num >= m->maxirqs)
		return -EINVAL;
	if (start >= m->alloc_start && start < m->alloc_end)
		which = MATRIX_RESERVE_INALLOC;
	irq_matrix_set(m, msk, start, num, which);
	return 0;
}

/**
 * irq_matrix_mark - Mark preallocated interrupts in the matrix
 * @m:		Pointer to the matrix which needs to be updated
 * @msk:	Which CPU maps need be updated
 * @start:	Start of the bitarea to mark
 * @num:	Number of bits to mark
 */
int irq_matrix_mark(struct irq_matrix *m, const struct cpumask *msk,
		    unsigned int start, unsigned int num)
{
	if (!num || start < m->alloc_start || start + num >= m->alloc_end)
		return -EINVAL;
	irq_matrix_set(m, msk, start, num, MATRIX_ALLOC);
	return 0;
}

static void irq_matrix_clear(struct irq_matrix *m,const struct cpumask *msk,
			     unsigned int start, unsigned int num, int which)
{
	unsigned int cpu;

	for_each_cpu(cpu, msk) {
		struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

		bitmap_clear(cm->map, start, num);
		cm->counters[which] -= num;
	}
}

/**
 * irq_matrix_free_reserved - Free reserved interrupts in the matrix
 * @m:		Pointer to the matrix which needs to be updated
 * @msk:	Which CPU maps need be updated
 * @start:	Start of the bitarea to free
 * @num:	Number of bits to free
 */
int irq_matrix_free_reserved(struct irq_matrix *m, const struct cpumask *msk,
			     unsigned int start, unsigned int num)
{
	int which = MATRIX_RESERVE;

	if (!num || start + num >= m->maxirqs)
		return -EINVAL;
	if (start >= m->alloc_start && start < m->alloc_end)
		which = MATRIX_RESERVE_INALLOC;
	irq_matrix_clear(m, msk, start, num, which);
	return 0;
}

/**
 * irq_matrix_free - Free allocated interrupts in the matrix
 * @m:		Pointer to the matrix which needs to be updated
 * @msk:	Which CPU maps need be updated
 * @start:	Start of the bitarea to free
 * @num:	Number of bits to free
 */
int irq_matrix_free(struct irq_matrix *m, const struct cpumask *msk,
		    unsigned int start, unsigned int num)
{
	if (!num || start < m->alloc_start || start + num >= m->alloc_end)
		return -EINVAL;
	irq_matrix_clear(m, msk, start, num, MATRIX_ALLOC);
	return 0;
}

static int irq_matrix_find_area(struct irq_matrix *m, unsigned long *irqmap,
				unsigned int num)
{
	unsigned int start = m->alloc_start;
	unsigned int end = m->alloc_end;
	unsigned long area;

	area = bitmap_find_next_zero_area(irqmap, end, start, num, 0);
	return area >= end ? -ENOSPC : (int) area;
}

/**
 * irq_matrix_alloc_single_target - Allocate interrupts in the matrix for one CPU
 * @m:		Pointer to the matrix to allocate from
 * @msk:	Which CPUs to search for the best free area
 * @num:	Number of bits to allocate
 * @mapped_cpu: Pointer to store the CPU for which the irqs were allocated
 */
int irq_matrix_alloc_single_target(struct irq_matrix *m,
				   const struct cpumask *msk,
				   unsigned int num,
				   unsigned int *mapped_cpu)
{
	unsigned int cpu;

	if (!num || num > m->alloc_end - m->alloc_start)
		return -EINVAL;

	for_each_cpu(cpu, msk) {
		struct cpumap *cm = per_cpu_ptr(m->maps, cpu);
		int area;

		area = irq_matrix_find_area(m, cm->map, num);
		if (area >= 0) {
			irq_matrix_set(m, cpumask_of(cpu), area, num,
				       MATRIX_ALLOC);
			*mapped_cpu = cpu;
			return area;
		}
	}
	return -ENOSPC;
}

/**
 * irq_matrix_get_next - Get the next active irq in a CPU allocation bitmap
 * @m:		Pointer to the matrix to search
 * @cpu:	Which CPU to search
 * @start:	Start of search
 */
unsigned int irq_matrix_get_next(struct irq_matrix *m, unsigned int cpu,
				 unsigned int start)
{
	struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

	if (start < m->alloc_start)
		start = m->alloc_start;
	return find_next_bit(cm->map, m->alloc_end, start);
}

/**
 * irq_matrix_available - Get the number of available irqs
 * @m:		Pointer to the matrix to query
 * @cpu:	Which CPU to get data for
 *
 * This returns the number of available irqs in the allocation area
 */
unsigned int irq_matrix_available(struct irq_matrix *m, unsigned int cpu)
{
	unsigned int asize = m->alloc_end -m->alloc_start;
	struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

	return asize - (cm->counters[MATRIX_ALLOC] +
			cm->counters[MATRIX_RESERVE_INALLOC]);
}

/**
 * irq_matrix_allocated - Get the number of allocated irqs
 * @m:		Pointer to the matrix to search
 * @cpu:	Which CPU to get data for
 *
 * This returns number of allocated irqs (excludes the bits which are marked
 * reserved in the allocation area)
 */
unsigned int irq_matrix_allocated(struct irq_matrix *m, unsigned int cpu)
{
	struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

	return cm->counters[MATRIX_ALLOC];
}

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
/**
 * irq_matrix_debug_show - Show detailed allocation information
 * @sf:		Pointer to the seq_file to print to
 * @m:		Pointer to the matrix allocator
 * @ind:	Indentation for the print format
 *
 * Note, this is a lockless snapshot.
 */
void irq_matrix_debug_show(struct seq_file *sf, struct irq_matrix *m, int ind)
{
	int cpu;

	seq_printf(sf, "%*sCPU  : resvd: alloc: vectors\n", ind, " ");
	cpus_read_lock();
	for_each_online_cpu(cpu) {
		struct cpumap *cm = per_cpu_ptr(m->maps, cpu);

		seq_printf(sf, "%*s%5d: %5u: %5u: %*pbl\n", ind, " ", cpu,
			   cm->counters[MATRIX_RESERVE] +
			   cm->counters[MATRIX_RESERVE_INALLOC],
			   cm->counters[MATRIX_ALLOC], m->maxirqs, cm->map);
	}
	cpus_read_unlock();
}
#endif
