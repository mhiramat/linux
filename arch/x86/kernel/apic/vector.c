/*
 * Local APIC related interfaces to support IOAPIC, MSI, HT_IRQ etc.
 *
 * Copyright (C) 1997, 1998, 1999, 2000, 2009 Ingo Molnar, Hajnalka Szabo
 *	Moved from arch/x86/kernel/apic/io_apic.c.
 * Jiang Liu <jiang.liu@linux.intel.com>
 *	Enable support of hierarchical irqdomains
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <asm/irqdomain.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/i8259.h>
#include <asm/desc.h>
#include <asm/irq_remapping.h>

#define NO_TARGET_CPU		(~0U)

struct apic_chip_data {
	struct irq_cfg		cfg;
	unsigned int		target_cpu;
	unsigned int		prev_target_cpu;
	u8			move_in_progress : 1;
};

struct irq_domain *x86_vector_domain;
EXPORT_SYMBOL_GPL(x86_vector_domain);
static DEFINE_RAW_SPINLOCK(vector_lock);
static cpumask_var_t vector_searchmask;
static struct irq_chip lapic_controller;
static struct irq_matrix *vector_matrix;

static inline bool cpu_inmask(unsigned int cpu, const struct cpumask *msk)
{
	return cpu != NO_TARGET_CPU && cpumask_test_cpu(cpu, msk);
}

static bool irq_is_legacy(int irq)
{
	/* Check whether the irq is in the legacy space */
	if (irq < 0 || irq >= nr_legacy_irqs())
		return false;
	/* Check whether the irq is handled by the IOAPIC */
	return !test_bit(irq, &io_apic_irqs);
}

void lock_vector_lock(void)
{
	/* Used to the online set of cpus does not change
	 * during assign_irq_vector.
	 */
	raw_spin_lock(&vector_lock);
}

void unlock_vector_lock(void)
{
	raw_spin_unlock(&vector_lock);
}

static struct apic_chip_data *apic_chip_data(struct irq_data *irq_data)
{
	if (!irq_data)
		return NULL;

	while (irq_data->parent_data)
		irq_data = irq_data->parent_data;

	return irq_data->chip_data;
}

struct irq_cfg *irqd_cfg(struct irq_data *irq_data)
{
	struct apic_chip_data *data = apic_chip_data(irq_data);

	return data ? &data->cfg : NULL;
}
EXPORT_SYMBOL_GPL(irqd_cfg);

struct irq_cfg *irq_cfg(unsigned int irq)
{
	return irqd_cfg(irq_get_irq_data(irq));
}

static struct apic_chip_data *alloc_apic_chip_data(int node)
{
	struct apic_chip_data *data;

	data = kzalloc_node(sizeof(*data), GFP_KERNEL, node);
	if (data) {
		data->target_cpu = NO_TARGET_CPU;
		data->prev_target_cpu = NO_TARGET_CPU;
	}
	return data;
}

static void free_apic_chip_data(struct apic_chip_data *data)
{
	kfree(data);
}

/*
 * Check all entries, whether there is still a move in progress or the
 * previous move has not been cleaned up completely.
 */
static bool irq_is_move_completed(struct apic_chip_data *apicd)
{
	return !apicd->move_in_progress &&
		!cpu_inmask(apicd->prev_target_cpu, cpu_online_mask);
}

static void
apic_update_irqcfg(int irq, int vec, unsigned int cpu,
		   struct apic_chip_data *apicd, struct irq_data *irqd)
{
	struct irq_desc *desc = irq_to_desc(irq);

	/* Set up the cleanup CPU, if necessary */
	if (apicd->cfg.vector &&
	    cpu_inmask(apicd->target_cpu, cpu_online_mask)) {
		apicd->move_in_progress = true;
		apicd->prev_target_cpu = apicd->target_cpu;
		apicd->cfg.old_vector = apicd->cfg.vector;
	} else {
		apicd->prev_target_cpu = NO_TARGET_CPU;
		apicd->cfg.old_vector = 0;
	}

	/* Set up the new data and cache the destination APIC id */
	apicd->cfg.vector = vec;
	apicd->target_cpu = cpu;

	/* Store the irq descriptor in the vector array */
	BUG_ON(!IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vec]));
	per_cpu(vector_irq, cpu)[vec] = desc;
}

static int
assign_single_cpu(int irq, struct cpumask *msk, struct apic_chip_data *apicd,
		  struct irq_data *irqd)
{
	unsigned int cpu = apicd->target_cpu;
	int vec;

	/*
	 * If the current target CPU is in the new requested affinity mask,
	 * there is no point in moving the interrupt from one CPU to
	 * another. Update the destination ID nevertheless, as this might be
	 * called from the legacy -> IOAPIC take over.
	 */
	if (apicd->cfg.vector && cpu_inmask(cpu, msk))
		goto setdest;

	vec = irq_matrix_alloc_single_target(vector_matrix, msk, 1, &cpu);
	if (vec < 0)
		return vec;

	apic_update_irqcfg(irq, vec, cpu, apicd, irqd);
setdest:
	apicd->cfg.dest_apicid = apic->calc_dest_apicid(cpu);
	irq_data_update_effective_affinity(irqd, cpumask_of(cpu));
	return 0;

}

static int assign_irq_vector_locked(int irq, const struct cpumask *affmask,
				    struct apic_chip_data *apicd,
				    struct irq_data *irqd)
{
	if (!irq_is_move_completed(apicd))
		return -EBUSY;

	/* Exclude offline CPUs from the allocation */
	cpumask_and(vector_searchmask, affmask, cpu_online_mask);
	/* No point in proceeding if the searchmask is empty */
	if (cpumask_empty(vector_searchmask))
		return -ENOSPC;
	return assign_single_cpu(irq, vector_searchmask, apicd, irqd);
}

static int assign_irq_vector(int irq, struct apic_chip_data *data,
			     const struct cpumask *mask,
			     struct irq_data *irqdata)
{
	int err;
	unsigned long flags;

	raw_spin_lock_irqsave(&vector_lock, flags);
	err = assign_irq_vector_locked(irq, mask, data, irqdata);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return err;
}

static int assign_irq_vector_policy(int irq, int node,
				    struct apic_chip_data *data,
				    struct irq_alloc_info *info,
				    struct irq_data *irqdata)
{
	if (info && info->mask)
		return assign_irq_vector(irq, data, info->mask, irqdata);
	if (node != NUMA_NO_NODE &&
	    assign_irq_vector(irq, data, cpumask_of_node(node), irqdata) == 0)
		return 0;
	return assign_irq_vector(irq, data, cpu_online_mask, irqdata);
}

static void clear_irq_vector(int irq, struct apic_chip_data *data)
{
	int cpu, vector;

	if (!data->cfg.vector)
		return;

	vector = data->cfg.vector;
	cpu = data->target_cpu;
	per_cpu(vector_irq, data->target_cpu)[vector] = VECTOR_UNUSED;
	irq_matrix_free(vector_matrix, cpumask_of(cpu), vector, 1);

	data->cfg.vector = 0;
	data->target_cpu = NO_TARGET_CPU;

	/*
	 * If the vector was pending for move or the cleanup IPI has not been
	 * processed yet, we need to remove the old references to desc from
	 * the previous target cpu vector table.
	 */
	cpu = data->prev_target_cpu;
	if (cpu != NO_TARGET_CPU) {
		vector = data->cfg.old_vector;
		per_cpu(vector_irq, cpu)[vector] = VECTOR_UNUSED;
		irq_matrix_free(vector_matrix, cpumask_of(cpu), vector, 1);
	}
	data->move_in_progress = 0;
	data->cfg.old_vector = 0;
	data->prev_target_cpu = NO_TARGET_CPU;
}

void init_irq_alloc_info(struct irq_alloc_info *info,
			 const struct cpumask *mask)
{
	memset(info, 0, sizeof(*info));
	info->mask = mask;
}

void copy_irq_alloc_info(struct irq_alloc_info *dst, struct irq_alloc_info *src)
{
	if (src)
		*dst = *src;
	else
		memset(dst, 0, sizeof(*dst));
}

static void x86_vector_free_irqs(struct irq_domain *domain,
				 unsigned int virq, unsigned int nr_irqs)
{
	struct apic_chip_data *apic_data;
	struct irq_data *irq_data;
	unsigned long flags;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(x86_vector_domain, virq + i);
		if (irq_data && irq_data->chip_data) {
			raw_spin_lock_irqsave(&vector_lock, flags);
			clear_irq_vector(virq + i, irq_data->chip_data);
			apic_data = irq_data->chip_data;
			irq_domain_reset_irq_data(irq_data);
			raw_spin_unlock_irqrestore(&vector_lock, flags);
			free_apic_chip_data(apic_data);
		}
	}
}

static int x86_vector_alloc_irqs(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_alloc_info *info = arg;
	struct apic_chip_data *data;
	struct irq_data *irq_data;
	int i, err, node;

	if (disable_apic)
		return -ENXIO;

	/* Currently vector allocator can't guarantee contiguous allocations */
	if ((info->flags & X86_IRQ_ALLOC_CONTIGUOUS_VECTORS) && nr_irqs > 1)
		return -ENOSYS;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(domain, virq + i);
		BUG_ON(!irq_data);
		node = irq_data_get_node(irq_data);
		WARN_ON_ONCE(irq_data->chip_data);

		data = alloc_apic_chip_data(node);
		if (!data) {
			err = -ENOMEM;
			goto error;
		}
		/*
		 * Make sure, that the legacy to IOAPIC transition stays on
		 * the same vector. This is required for check_timer() to
		 * work correctly as it might switch back to legacy mode.
		 */
		if (info->flags & X86_IRQ_ALLOC_LEGACY) {
			data->cfg.vector = ISA_IRQ_VECTOR(virq + i);
			data->target_cpu = 0;
		}
		irq_data->chip = &lapic_controller;
		irq_data->chip_data = data;
		irq_data->hwirq = virq + i;
		irqd_set_single_target(irq_data);
		err = assign_irq_vector_policy(virq + i, node, data, info,
					       irq_data);
		if (err)
			goto error;
	}

	return 0;

error:
	x86_vector_free_irqs(domain, virq, i + 1);
	return err;
}

static const struct irq_domain_ops x86_vector_domain_ops = {
	.alloc	= x86_vector_alloc_irqs,
	.free	= x86_vector_free_irqs,
};

int __init arch_probe_nr_irqs(void)
{
	int nr;

	if (nr_irqs > (NR_VECTORS * nr_cpu_ids))
		nr_irqs = NR_VECTORS * nr_cpu_ids;

	nr = (gsi_top + nr_legacy_irqs()) + 8 * nr_cpu_ids;
#if defined(CONFIG_PCI_MSI) || defined(CONFIG_HT_IRQ)
	/*
	 * for MSI and HT dyn irq
	 */
	if (gsi_top <= NR_IRQS_LEGACY)
		nr +=  8 * nr_cpu_ids;
	else
		nr += gsi_top * 16;
#endif
	if (nr < nr_irqs)
		nr_irqs = nr;

	/*
	 * We don't know if PIC is present at this point so we need to do
	 * probe() to get the right number of legacy IRQs.
	 */
	return legacy_pic->probe();
}

void lapic_reserve_system_vectors(void)
{
	const struct cpumask *msk = cpumask_of(smp_processor_id());
	int vec = 0;

	for_each_set_bit_from(vec, reserved_vectors, NR_VECTORS)
		irq_matrix_reserve(vector_matrix, msk, vec, 1);
}

static void lapic_reserve_legacy_vector(unsigned int irq)
{
	const struct cpumask *msk = cpumask_of(smp_processor_id());

	/*
	 * Use reserve here so it wont get accounted as allocated and
	 * moveable in the cpu hotplug check.
	 */
	irq_matrix_reserve(vector_matrix, msk, ISA_IRQ_VECTOR(irq), 1);
}

void __init lapic_mark_legacy_vector(unsigned int irq)
{
	const struct cpumask *msk = cpumask_of(smp_processor_id());

	if (irq != PIC_CASCADE_IR)
		irq_matrix_mark(vector_matrix, msk, ISA_IRQ_VECTOR(irq), 1);
	else
		lapic_reserve_legacy_vector(irq);
}

int __init arch_early_irq_init(void)
{
	struct fwnode_handle *fn;

	fn = irq_domain_alloc_named_fwnode("VECTOR");
	BUG_ON(!fn);
	x86_vector_domain = irq_domain_create_tree(fn, &x86_vector_domain_ops,
						   NULL);
	BUG_ON(x86_vector_domain == NULL);
	irq_domain_free_fwnode(fn);
	irq_set_default_host(x86_vector_domain);

	arch_init_msi_domain(x86_vector_domain);
	arch_init_htirq_domain(x86_vector_domain);

	BUG_ON(!alloc_cpumask_var(&vector_searchmask, GFP_KERNEL));

	/*
	 * Allocate the vector matrix allocator data structure and limit the
	 * search area.
	 */
	vector_matrix = irq_alloc_matrix(NR_VECTORS, FIRST_EXTERNAL_VECTOR,
					 FIRST_SYSTEM_VECTOR);
	BUG_ON(!vector_matrix);

	return arch_early_ioapic_init();
}

static struct irq_desc *__setup_vector_irq(int vector)
{
	int isairq = vector - ISA_IRQ_VECTOR(0);

	if (!irq_is_legacy(isairq))
		return VECTOR_UNUSED;

	/* Legacy irq found */
	lapic_reserve_legacy_vector(isairq);
	return irq_to_desc(isairq);
}

/*
 * Setup the vector to irq mappings. Must be called with vector_lock held.
 */
void setup_vector_irq(int cpu)
{
	int vector;

	lockdep_assert_held(&vector_lock);

	/* Clear out the vector matrix array for this CPU */
	irq_matrix_reset(vector_matrix, cpumask_of(cpu));
	/* Reserve the system vectors in the external irq vector space */
	lapic_reserve_system_vectors();
	/*
	 * The interrupt affinity logic never targets interrupts to offline
	 * CPUs. The exception are the legacy PIC interrupts. In general
	 * they are only targeted to CPU0, but depending on the platform
	 * they can be distributed to any online CPU in hardware. The
	 * kernel has no influence on that. So all active legacy vectors
	 * must be installed on all CPUs. All non legacy interrupts can be
	 * cleared.
	 */
	for (vector = 0; vector < NR_VECTORS; vector++)
		per_cpu(vector_irq, cpu)[vector] = __setup_vector_irq(vector);
}

static int apic_retrigger_irq(struct irq_data *irq_data)
{
	struct apic_chip_data *data = apic_chip_data(irq_data);
	unsigned int cpu = data->target_cpu;
	unsigned long flags;

	if (cpu != NO_TARGET_CPU) {
		raw_spin_lock_irqsave(&vector_lock, flags);
		apic->send_IPI_mask(cpumask_of(cpu), data->cfg.vector);
		raw_spin_unlock_irqrestore(&vector_lock, flags);
	}
	return 1;
}

void apic_ack_edge(struct irq_data *data)
{
	irq_complete_move(irqd_cfg(data));
	irq_move_irq(data);
	ack_APIC_irq();
}

static int apic_set_affinity(struct irq_data *irq_data,
			     const struct cpumask *dest, bool force)
{
	struct apic_chip_data *data = irq_data->chip_data;
	int err, irq = irq_data->irq;

	if (!IS_ENABLED(CONFIG_SMP))
		return -EPERM;

	if (!cpumask_intersects(dest, cpu_online_mask))
		return -EINVAL;

	err = assign_irq_vector(irq, data, dest, irq_data);
	return err ? err : IRQ_SET_MASK_OK;
}

static struct irq_chip lapic_controller = {
	.name			= "APIC",
	.irq_ack		= apic_ack_edge,
	.irq_set_affinity	= apic_set_affinity,
	.irq_retrigger		= apic_retrigger_irq,
};

#ifdef CONFIG_SMP
static void __send_cleanup_vector(struct apic_chip_data *data)
{
	unsigned int cpu = data->prev_target_cpu;

	raw_spin_lock(&vector_lock);
	data->move_in_progress = 0;
	if (cpu_inmask(cpu, cpu_online_mask))
		apic->send_IPI_mask(cpumask_of(cpu), IRQ_MOVE_CLEANUP_VECTOR);
	raw_spin_unlock(&vector_lock);
}

void send_cleanup_vector(struct irq_cfg *cfg)
{
	struct apic_chip_data *data;

	data = container_of(cfg, struct apic_chip_data, cfg);
	if (data->move_in_progress)
		__send_cleanup_vector(data);
}

asmlinkage __visible void __irq_entry smp_irq_move_cleanup_interrupt(void)
{
	unsigned vector, me;

	entering_ack_irq();

	/* Prevent vectors vanishing under us */
	raw_spin_lock(&vector_lock);

	me = smp_processor_id();
	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		struct apic_chip_data *data;
		struct irq_desc *desc;
		unsigned int irr;

	retry:
		desc = __this_cpu_read(vector_irq[vector]);
		if (IS_ERR_OR_NULL(desc))
			continue;

		if (!raw_spin_trylock(&desc->lock)) {
			raw_spin_unlock(&vector_lock);
			cpu_relax();
			raw_spin_lock(&vector_lock);
			goto retry;
		}

		data = apic_chip_data(irq_desc_get_irq_data(desc));
		if (!data)
			goto unlock;

		/*
		 * Nothing to cleanup if irq migration is in progress or
		 * this cpu is not the target or the cleanup vector does
		 * not match.
		 */
		if (data->move_in_progress || me != data->prev_target_cpu ||
		    data->cfg.vector != vector)
			goto unlock;

		irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
		/*
		 * Check if the vector that needs to be cleanedup is
		 * registered at the cpu's IRR. If so, then this is not
		 * the best time to clean it up. Lets clean it up in the
		 * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
		 * to myself.
		 */
		if (irr  & (1 << (vector % 32))) {
			apic->send_IPI_self(IRQ_MOVE_CLEANUP_VECTOR);
			goto unlock;
		}
		__this_cpu_write(vector_irq[vector], VECTOR_UNUSED);
		data->prev_target_cpu = NO_TARGET_CPU;
		irq_matrix_free(vector_matrix, cpumask_of(me), vector, 1);
unlock:
		raw_spin_unlock(&desc->lock);
	}

	raw_spin_unlock(&vector_lock);

	exiting_irq();
}

static void __irq_complete_move(struct irq_cfg *cfg, unsigned vector)
{
	unsigned me;
	struct apic_chip_data *data;

	data = container_of(cfg, struct apic_chip_data, cfg);
	if (likely(!data->move_in_progress))
		return;

	me = smp_processor_id();
	if (vector == data->cfg.vector && me == data->target_cpu)
		__send_cleanup_vector(data);
}

void irq_complete_move(struct irq_cfg *cfg)
{
	__irq_complete_move(cfg, ~get_irq_regs()->orig_ax);
}

/*
 * Called from fixup_irqs() with @desc->lock held and interrupts disabled.
 */
void irq_force_complete_move(struct irq_desc *desc)
{
	struct irq_data *irqdata;
	struct apic_chip_data *data;
	struct irq_cfg *cfg;
	unsigned int cpu;

	/*
	 * The function is called for all descriptors regardless of which
	 * irqdomain they belong to. For example if an IRQ is provided by
	 * an irq_chip as part of a GPIO driver, the chip data for that
	 * descriptor is specific to the irq_chip in question.
	 *
	 * Check first that the chip_data is what we expect
	 * (apic_chip_data) before touching it any further.
	 */
	irqdata = irq_domain_get_irq_data(x86_vector_domain,
					  irq_desc_get_irq(desc));
	if (!irqdata)
		return;

	data = apic_chip_data(irqdata);
	cfg = data ? &data->cfg : NULL;

	if (!cfg)
		return;

	/*
	 * This is tricky. If the cleanup of @data->old_domain has not been
	 * done yet, then the following setaffinity call will fail with
	 * -EBUSY. This can leave the interrupt in a stale state.
	 *
	 * All CPUs are stuck in stop machine with interrupts disabled so
	 * calling __irq_complete_move() would be completely pointless.
	 */
	raw_spin_lock(&vector_lock);

	/*
	 * If move_in_progress is cleared and the outgoing CPU was the
	 * previous target, then there is nothing to cleanup. fixup_irqs()
	 * will take care of the stale vectors on the outgoing cpu.
	 */
	if (!data->move_in_progress &&
	    !cpu_inmask(data->prev_target_cpu, cpu_online_mask)) {
		raw_spin_unlock(&vector_lock);
		return;
	}

	/*
	 * 1) The interrupt is in move_in_progress state. That means that we
	 *    have not seen an interrupt since the io_apic was reprogrammed to
	 *    the new vector.
	 *
	 * 2) The interrupt has fired on the new vector, but the cleanup IPIs
	 *    have not been processed yet.
	 */
	if (data->move_in_progress) {
		/*
		 * In theory there is a race:
		 *
		 * set_ioapic(new_vector) <-- Interrupt is raised before update
		 *			      is effective, i.e. it's raised on
		 *			      the old vector.
		 *
		 * So if the target cpu cannot handle that interrupt before
		 * the old vector is cleaned up, we get a spurious interrupt
		 * and in the worst case the ioapic irq line becomes stale.
		 *
		 * But in case of cpu hotplug this should be a non issue
		 * because if the affinity update happens right before all
		 * cpus rendevouz in stop machine, there is no way that the
		 * interrupt can be blocked on the target cpu because all cpus
		 * loops first with interrupts enabled in stop machine, so the
		 * old vector is not yet cleaned up when the interrupt fires.
		 *
		 * So the only way to run into this issue is if the delivery
		 * of the interrupt on the apic/system bus would be delayed
		 * beyond the point where the target cpu disables interrupts
		 * in stop machine. I doubt that it can happen, but at least
		 * there is a theroretical chance. Virtualization might be
		 * able to expose this, but AFAICT the IOAPIC emulation is not
		 * as stupid as the real hardware.
		 *
		 * Anyway, there is nothing we can do about that at this point
		 * w/o refactoring the whole fixup_irq() business completely.
		 * We print at least the irq number and the old vector number,
		 * so we have the necessary information when a problem in that
		 * area arises.
		 */
		pr_warn("IRQ fixup: irq %d move in progress, old vector %d\n",
			irqdata->irq, cfg->old_vector);
	}
	/*
	 * If the prev_target_cpu still has the old vector set, clean it up.
	 */
	cpu = data->prev_target_cpu;
	if (cpu_inmask(cpu, cpu_online_mask)) {
		per_cpu(vector_irq, cpu)[cfg->old_vector] = VECTOR_UNUSED;
		irq_matrix_free(vector_matrix, cpumask_of(cpu),
				cfg->old_vector, 1);
	}
	/* Cleanup the left overs of the (half finished) move */
	data->move_in_progress = 0;
	data->prev_target_cpu = NO_TARGET_CPU;
	raw_spin_unlock(&vector_lock);
}
#endif

static void __init print_APIC_field(int base)
{
	int i;

	printk(KERN_DEBUG);

	for (i = 0; i < 8; i++)
		pr_cont("%08x", apic_read(base + i*0x10));

	pr_cont("\n");
}

static void __init print_local_APIC(void *dummy)
{
	unsigned int i, v, ver, maxlvt;
	u64 icr;

	pr_debug("printing local APIC contents on CPU#%d/%d:\n",
		 smp_processor_id(), hard_smp_processor_id());
	v = apic_read(APIC_ID);
	pr_info("... APIC ID:      %08x (%01x)\n", v, read_apic_id());
	v = apic_read(APIC_LVR);
	pr_info("... APIC VERSION: %08x\n", v);
	ver = GET_APIC_VERSION(v);
	maxlvt = lapic_get_maxlvt();

	v = apic_read(APIC_TASKPRI);
	pr_debug("... APIC TASKPRI: %08x (%02x)\n", v, v & APIC_TPRI_MASK);

	/* !82489DX */
	if (APIC_INTEGRATED(ver)) {
		if (!APIC_XAPIC(ver)) {
			v = apic_read(APIC_ARBPRI);
			pr_debug("... APIC ARBPRI: %08x (%02x)\n",
				 v, v & APIC_ARBPRI_MASK);
		}
		v = apic_read(APIC_PROCPRI);
		pr_debug("... APIC PROCPRI: %08x\n", v);
	}

	/*
	 * Remote read supported only in the 82489DX and local APIC for
	 * Pentium processors.
	 */
	if (!APIC_INTEGRATED(ver) || maxlvt == 3) {
		v = apic_read(APIC_RRR);
		pr_debug("... APIC RRR: %08x\n", v);
	}

	v = apic_read(APIC_LDR);
	pr_debug("... APIC LDR: %08x\n", v);
	if (!x2apic_enabled()) {
		v = apic_read(APIC_DFR);
		pr_debug("... APIC DFR: %08x\n", v);
	}
	v = apic_read(APIC_SPIV);
	pr_debug("... APIC SPIV: %08x\n", v);

	pr_debug("... APIC ISR field:\n");
	print_APIC_field(APIC_ISR);
	pr_debug("... APIC TMR field:\n");
	print_APIC_field(APIC_TMR);
	pr_debug("... APIC IRR field:\n");
	print_APIC_field(APIC_IRR);

	/* !82489DX */
	if (APIC_INTEGRATED(ver)) {
		/* Due to the Pentium erratum 3AP. */
		if (maxlvt > 3)
			apic_write(APIC_ESR, 0);

		v = apic_read(APIC_ESR);
		pr_debug("... APIC ESR: %08x\n", v);
	}

	icr = apic_icr_read();
	pr_debug("... APIC ICR: %08x\n", (u32)icr);
	pr_debug("... APIC ICR2: %08x\n", (u32)(icr >> 32));

	v = apic_read(APIC_LVTT);
	pr_debug("... APIC LVTT: %08x\n", v);

	if (maxlvt > 3) {
		/* PC is LVT#4. */
		v = apic_read(APIC_LVTPC);
		pr_debug("... APIC LVTPC: %08x\n", v);
	}
	v = apic_read(APIC_LVT0);
	pr_debug("... APIC LVT0: %08x\n", v);
	v = apic_read(APIC_LVT1);
	pr_debug("... APIC LVT1: %08x\n", v);

	if (maxlvt > 2) {
		/* ERR is LVT#3. */
		v = apic_read(APIC_LVTERR);
		pr_debug("... APIC LVTERR: %08x\n", v);
	}

	v = apic_read(APIC_TMICT);
	pr_debug("... APIC TMICT: %08x\n", v);
	v = apic_read(APIC_TMCCT);
	pr_debug("... APIC TMCCT: %08x\n", v);
	v = apic_read(APIC_TDCR);
	pr_debug("... APIC TDCR: %08x\n", v);

	if (boot_cpu_has(X86_FEATURE_EXTAPIC)) {
		v = apic_read(APIC_EFEAT);
		maxlvt = (v >> 16) & 0xff;
		pr_debug("... APIC EFEAT: %08x\n", v);
		v = apic_read(APIC_ECTRL);
		pr_debug("... APIC ECTRL: %08x\n", v);
		for (i = 0; i < maxlvt; i++) {
			v = apic_read(APIC_EILVTn(i));
			pr_debug("... APIC EILVT%d: %08x\n", i, v);
		}
	}
	pr_cont("\n");
}

static void __init print_local_APICs(int maxcpu)
{
	int cpu;

	if (!maxcpu)
		return;

	preempt_disable();
	for_each_online_cpu(cpu) {
		if (cpu >= maxcpu)
			break;
		smp_call_function_single(cpu, print_local_APIC, NULL, 1);
	}
	preempt_enable();
}

static void __init print_PIC(void)
{
	unsigned int v;
	unsigned long flags;

	if (!nr_legacy_irqs())
		return;

	pr_debug("\nprinting PIC contents\n");

	raw_spin_lock_irqsave(&i8259A_lock, flags);

	v = inb(0xa1) << 8 | inb(0x21);
	pr_debug("... PIC  IMR: %04x\n", v);

	v = inb(0xa0) << 8 | inb(0x20);
	pr_debug("... PIC  IRR: %04x\n", v);

	outb(0x0b, 0xa0);
	outb(0x0b, 0x20);
	v = inb(0xa0) << 8 | inb(0x20);
	outb(0x0a, 0xa0);
	outb(0x0a, 0x20);

	raw_spin_unlock_irqrestore(&i8259A_lock, flags);

	pr_debug("... PIC  ISR: %04x\n", v);

	v = inb(0x4d1) << 8 | inb(0x4d0);
	pr_debug("... PIC ELCR: %04x\n", v);
}

static int show_lapic __initdata = 1;
static __init int setup_show_lapic(char *arg)
{
	int num = -1;

	if (strcmp(arg, "all") == 0) {
		show_lapic = CONFIG_NR_CPUS;
	} else {
		get_option(&arg, &num);
		if (num >= 0)
			show_lapic = num;
	}

	return 1;
}
__setup("show_lapic=", setup_show_lapic);

static int __init print_ICs(void)
{
	if (apic_verbosity == APIC_QUIET)
		return 0;

	print_PIC();

	/* don't print out if apic is not there */
	if (!boot_cpu_has(X86_FEATURE_APIC) && !apic_from_smp_config())
		return 0;

	print_local_APICs(show_lapic);
	print_IO_APICs();

	return 0;
}

late_initcall(print_ICs);
