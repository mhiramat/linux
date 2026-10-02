.. SPDX-License-Identifier: GPL-2.0

=============================================================
Kprobes Jump Optimization Architecture & State Machine Design
=============================================================

:Author: Masami Hiramatsu <mhiramat@kernel.org>
:Date: October 2026

.. contents:: Table of Contents
   :depth: 2

Overview
========

Kprobes allows developers to dynamically instrument almost any kernel routine
with minimal runtime overhead. When ``CONFIG_OPTPROBES=y`` is enabled, kprobes
reduces probe-hit latency by replacing software breakpoint trap instructions
(e.g., ``INT3`` on x86) with direct relative jump instructions to a detour
trampoline buffer.

The multi-generational asynchronous jump optimizer decouples instruction
patching from Tasks RCU grace period waiting. Instead of blocking the caller or
holding system-wide locks (such as ``text_mutex`` and ``cpus_read_lock``)
across synchronous grace periods (which could stall for seconds or minutes under
preempt-lazy or compute-intensive workloads), probe optimization and
unoptimization are processed asynchronously using a bounded ring of generations
and ``call_rcu_tasks()``.

This document describes the structural relationships between user kprobes and
aggregator optprobes, the detour trampoline execution modes, the generational
ring architecture, and the complete 13-state lifecycle state machine.


1. Structural Relationship: User Kprobe vs. Aggrprobe (Optprobe)
================================================================

In the Linux kernel kprobes subsystem, an optimized kprobe
(``struct optimized_kprobe *op``) is an aggregator kprobe (aggrprobe) that
manages jump-detour execution for one or more user-registered kprobes located
at the same probe address.

::

    +-------------------------------------------------------------------+
    | struct optimized_kprobe (op)                                      |
    |                                                                   |
    |   +-----------------------------------------------------------+   |
    |   | struct kprobe kp (the Aggregator "ap")                    |   |
    |   |   .addr = target_address                                  |   |
    |   |   .hlist ----> Linked in global kprobe_table[hash]        |   |
    |   |   .pre_handler = aggr_pre_handler                         |   |
    |   |   .flags = (KPROBE_FLAG_OPTIMIZED, DISABLED, etc.)        |   |
    |   |   .list -----------------------------+                    |   |
    |   +--------------------------------------|--------------------+   |
    |   .optinsn (Detour Trampoline Buffer)    |                        |
    |   .list (Queue: optimizing, unopt, etc.) |                        |
    |   +--------------------------------------|--------------------+   |
    +------------------------------------------|------------------------+
                                               |
             +---------------------------------+
             |
             v (RCU-protected child list of User Kprobes)
       +-----------------------+     +-----------------------+
       | struct kprobe (p1)    |     | struct kprobe (p2)    |
       |  .pre_handler = user1 |     |  .pre_handler = user2 |
       |  .flags = (ENABLED)   | --> |  .flags = (DISABLED)  | --> NULL
       |  .list                |     |  .list                |
       +-----------------------+     +-----------------------+

Roles and Definitions
---------------------

User Kprobe (``struct kprobe *p``)
    Registered by kernel modules, BPF programs, or tracing subsystems via
    ``register_kprobe(p)``. It is attached to the aggregator's child list
    (``ap->list``). User kprobes never join optimizer generation queues
    directly.

Aggregator Probe (``ap = &op->kp``)
    The primary anchor kprobe hashed in ``kprobe_table[]``. It holds the
    composite flags, dispatches handler callbacks sequentially across
    active children, and interfaces with kernel instruction modification.

Detour Trampoline (``op->optinsn``)
    Allocated from an architecture-specific executable instruction slot. It
    contains instructions to save CPU registers, invoke ``opt_pre_handler()``,
    execute relocated original instructions out of line, and jump back to the
    original instruction stream.


2. Multi-Generational Asynchronous Optimizer Architecture
=========================================================

The optimizer manages probes through a fixed ring of generation structures::

    struct optprobe_generation optprobe_gens[OPTPROBE_GEN_MAX];

Generations avoid dynamic heap allocation (and potential ``-ENOMEM`` failures
during optimization) by using statically bounded queues.

The Four Generation Probe Lists
-------------------------------

Each ``struct optprobe_generation`` contains four distinct probe lists:

``optimizing_list``
    Holds probes waiting for the Tasks RCU grace period to drain all tasks from
    the original instruction bytes before installing the 5-byte relative jump.

``unoptimizing_list``
    Acts as a staging queue for batching unoptimization requests (replacing
    relative jumps with breakpoints). This is not a wait queue for a grace
    period; text unoptimization happens immediately upon generation dispatch.

``cooling_list``
    Holds in-use probes whose jumps were replaced with breakpoints, waiting for
    the Tasks RCU grace period to drain all tasks executing inside the
    ``optinsn`` detour slot. Holding probes on this list keeps
    ``list_empty(&op->list)`` false, preventing concurrent
    ``unregister_kprobes()`` from prematurely freeing the aggregator probe or
    detour buffer while preempted tasks remain inside.

``freeing_list``
    Holds unused aggregator probes that are already unhashed from
    ``kprobe_table[]`` (via ``hlist_del_init_rcu``) and are waiting for batch
    release (freeing detour slots and memory via ``free_aggr_kprobe()``) after
    the Tasks RCU grace period completes.

The Waiting Room Invariant
--------------------------

To guarantee an idle generation is always available to collect incoming probe
requests without dynamic allocation, the current generation
(``optprobe_cur_gen``) serves as the "waiting room".

The waiting room generation is never dispatched to Tasks RCU until another
in-flight generation has finished. When dispatched, ``optprobe_cur_gen``
advances to the next slot in the ring, and ``call_rcu_tasks()`` is invoked
asynchronously.


3. Detour Execution Modes
=========================

A fundamental architectural detail is how CPU execution paths interact with
the detour trampoline across its lifecycle:

DETOUR_INACTIVE
---------------

- ``KPROBE_FLAG_OPTIMIZED`` is cleared (0).
- Text contains ``INT3`` or original instruction bytes.
- Hits at ``p->addr`` are handled via single-stepping (``setup_singlestep()``).

DETOUR_ACTIVE_VIA_INT3 (Trap-Based Detour)
------------------------------------------

- When ``optimize_kprobe(ap)`` is invoked, it sets
  ``ap->flags |= KPROBE_FLAG_OPTIMIZED`` and enqueues ``op->list`` onto
  ``optimizing_list``.
- Kernel text still contains ``INT3``; the 5-byte jump has not yet been
  patched.
- When a CPU hits the ``INT3`` trap, ``kprobe_handler()`` calls
  ``setup_singlestep()`` -> ``setup_detour_execution()``.
- Because ``KPROBE_FLAG_OPTIMIZED`` is set, ``setup_detour_execution()``
  redirects ``regs->ip`` directly to ``op->optinsn.insn + TMPL_END_IDX``,
  bypassing instruction emulation and single-stepping.
- **Crucial Invariant**: The detour code is actively executed by CPUs while
  queued in ``optimizing_list``.

DETOUR_ACTIVE_VIA_JMP (Direct Jump Detour)
------------------------------------------

- When the optimizer completes the generation's grace period, it executes
  ``arch_optimize_kprobes()``, replacing ``INT3`` with a 5-byte relative jump.
- ``op->list`` is removed from ``optimizing_list`` (``NOT_QUEUED``).
- CPUs bypass breakpoint trap exceptions entirely and jump directly into
  ``op->optinsn``.

DETOUR_DRAINING (Tasks RCU in Flight)
-------------------------------------

- ``optprobe_dispatch_generation()`` executes ``do_unoptimize_kprobes()``.
- ``arch_unoptimize_kprobes()`` replaces the relative jump with an ``INT3``
  breakpoint and restores the trailing original instruction bytes.
- ``op->kp.flags &= ~KPROBE_FLAG_OPTIMIZED`` clears the optimization flag.
- With the flag cleared, ``setup_detour_execution()`` will no longer route
  new ``INT3`` hits to the detour buffer.
- No new entries into the detour code can occur.
- Preempted tasks still inside the trampoline continue executing towards the
  trampoline exit during the Tasks RCU grace period (on ``cooling_list``).

DETOUR_QUIESCENT (Cold)
-----------------------

- The Tasks RCU grace period has completed (``optprobe_generation_rcu_cb()``).
- Exactly zero tasks remain executing inside the detour trampoline.
- The detour slot is safe to be reclaimed or re-optimized.


4. State Machine Transitions
============================

The lifecycle of an optimized kprobe encompasses 13 discrete states.

State Flow Diagram
------------------

::

                              [ UNREGISTERED ]
                                     |
                                     | register_kprobe()
                                     v
                 +------------> [ ARMED_INT3 ] <------------+
                 |               |         ^                |
   disable_kprobe|  enable_kprobe|         | sysctl=0       | force=true
                 v               |         | unoptimize     | unoptimize
         [ DISARMED_INT3 ]       |         |                |
                 ^               v         |                |
                 |       [ OPT_QUEUED ]----+                |
   disable/      |               |                          |
   disarm        +---------------+ (if disabled)            |
                                 |                          |
                                 | dispatch_gen             |
                                 | (patch 5B JMP)           |
                                 v                          |
                           [ OPTIMIZED ] -------------------+
                                 |
                                 | unoptimize_kprobe(force=false)
                                 v
                          [ UNOPT_QUEUED ]
                                 |
                                 | dispatch_gen (patch INT3)
                                 | call_rcu_tasks()
                                 v
                          [ COOLING_ARMED ]
                                 |
               +-----------------+-----------------+
               |                                   |
               | disable_kprobe                    | unregister_kprobe
               v                                   v
      [ COOLING_DISARMED ]                 [ COOLING_UNUSED ]
               |                                   |
               | Tasks RCU expires                 | Tasks RCU expires
               v                                   v
       [ DISARMED_INT3 ]                  [ UNHASHED_DRAINING ]
                                                   |
                                                   | Standard RCU expires
                                                   v
                                             [ RECLAIMED ]

   Module Unload Path (MODULE_STATE_GOING):
   ----------------------------------------
     In-Use Probes (ap->list >= 1):
       ARMED_INT3, DISARMED_INT3, OPT_QUEUED, OPTIMIZED,
       UNOPT_QUEUED, COOLING_ARMED, COOLING_DISARMED
                   |
                   v
                [ GONE ] ---> unregister_kprobe(last child) ---> [ RECLAIMED ]

     Unused Aggrprobes (ap->list == EMPTY):
       COOLING_UNUSED
                   |
                   v
             [ GONE_UNUSED ] ---> Tasks RCU expires ---> [ RECLAIMED ]

State Descriptions and Triggers
-------------------------------

UNREGISTERED
    Initial or final state. The probe is not registered in the system.

ARMED_INT3
    Instruction has a 1-byte software breakpoint (``INT3``). Detour
    trampoline is inactive.
    Trigger: ``register_kprobe(p)`` or re-enabling a disabled probe.

DISARMED_INT3
    Instruction has original instruction bytes restored. Aggregator probe
    remains hashed in ``kprobe_table[]``.
    Trigger: ``disable_kprobe(p)`` when all child probes are disabled.

OPT_QUEUED
    Probe is queued on ``optprobe_cur_gen.optimizing_list``. Text still holds
    ``INT3``. ``KPROBE_FLAG_OPTIMIZED`` is set; breakpoint hits redirect to the
    detour.
    Trigger: ``optimize_kprobe(ap)``.

OPTIMIZED
    Instruction contains a 5-byte relative jump (``JMP``). CPUs jump directly
    into the detour buffer without trap overhead.
    Trigger: ``arch_optimize_kprobes()`` executed by the optimizer thread.

UNOPT_QUEUED
    Probe is queued on ``optprobe_cur_gen.unoptimizing_list``. Instruction
    still has the 5-byte jump active.
    Trigger: ``unoptimize_kprobe(ap, force=false)`` upon probe disable,
    unregister, or sysctl unoptimization.

COOLING_ARMED
    Jump has been replaced with ``INT3``, and optimization flag is cleared.
    Detour trampoline is draining under Tasks RCU (``gen->cooling_list``).
    Trigger: ``optprobe_dispatch_generation()``.

COOLING_DISARMED
    Jump was replaced with ``INT3``, and then disarmed to original bytes.
    Detour trampoline is draining under Tasks RCU (``gen->cooling_list``).
    Trigger: ``disable_kprobe()`` while on ``cooling_list``.

COOLING_UNUSED
    All user child probes have been unregistered (``ap->list`` is empty).
    Kept on ``cooling_list`` and hashed in ``kprobe_table[]`` to prevent
    premature reclamation.
    Trigger: ``unregister_kprobes()`` while probe is cooling.

UNHASHED_DRAINING
    Tasks RCU grace period has completed. Detour buffer is cold. Aggregator
    probe is unhashed from ``kprobe_table[]`` (``hlist_del_init_rcu``).
    Waiting for a Standard RCU grace period before freeing memory.
    Trigger: Tasks RCU callback on an unused probe.

RECLAIMED
    Detour trampoline instruction slot is freed
    (``arch_remove_optimized_kprobe()``). Aggregator struct is released via
    ``kfree()``.

GONE (Module Unloaded, In-Use)
    Target module containing the probed code was unloaded. Probes had at least
    one active user registration. Marked with ``KPROBE_FLAG_GONE`` and kept in
    ``kprobe_table[]`` to reject future ``enable_kprobe()`` attempts with
    ``-EINVAL``. Memory is reclaimed only when the user calls
    ``unregister_kprobe()`` on the last child probe.

GONE_UNUSED (Module Unloaded, Unused)
    Target module was unloaded while an aggregator probe was on
    ``cooling_list`` with zero children (``kprobe_unused() == true``).
    Unhashed immediately and queued to ``cur_gen.freeing_list``.
    Detour trampoline is guaranteed **QUIESCENT** (0 tasks) because the module
    loader guarantees no CPUs remain inside module code. Automatically
    reclaimed by ``do_free_cleaned_kprobes()`` without user intervention.


5. State Matrix
===============

.. list-table:: Kprobe Optimization State Matrix
   :widths: 16 14 22 14 12 12 18
   :header-rows: 1

   * - State Name
     - Queue (``op->list``)
     - Detour Trampoline Execution
     - Text Instruction
     - Hash Table
     - Child Probes
     - In-Flight Grace Period

   * - **ARMED_INT3**
     - None
     - INACTIVE
     - ``INT3`` (1 byte)
     - Hashed
     - >= 1 active
     - None

   * - **DISARMED_INT3**
     - None
     - INACTIVE
     - ORIGINAL bytes
     - Hashed
     - All disabled
     - None

   * - **OPT_QUEUED**
     - ``optimizing_list``
     - ACTIVE via ``INT3`` trap
     - ``INT3`` (1 byte)
     - Hashed
     - >= 1 active
     - None (waiting in gen)

   * - **OPTIMIZED**
     - None
     - ACTIVE via direct ``JMP``
     - ``JMP`` (5 bytes)
     - Hashed
     - >= 1 active
     - None

   * - **UNOPT_QUEUED**
     - ``unoptimizing_list``
     - ACTIVE via direct ``JMP``
     - ``JMP`` (still live)
     - Hashed
     - >= 1 active
     - None (waiting in gen)

   * - **COOLING_ARMED**
     - ``cooling_list``
     - DRAINING (no new entries)
     - ``INT3`` (1 byte)
     - Hashed
     - >= 1 active
     - Tasks RCU

   * - **COOLING_DISARMED**
     - ``cooling_list``
     - DRAINING (no new entries)
     - ORIGINAL bytes
     - Hashed
     - All disabled
     - Tasks RCU

   * - **COOLING_UNUSED**
     - ``cooling_list``
     - DRAINING (no new entries)
     - ``INT3`` or ORIGINAL
     - Hashed
     - EMPTY (0)
     - Tasks RCU

   * - **UNHASHED_DRAINING**
     - ``freeing_list`` / RCU
     - QUIESCENT (Cold, 0 tasks)
     - ORIGINAL bytes
     - UNLINKED
     - EMPTY (0)
     - Standard RCU

   * - **RECLAIMED**
     - None
     - Slot removed
     - ORIGINAL bytes
     - UNLINKED
     - EMPTY (0)
     - None

   * - **GONE**
     - None
     - Reclaimed
     - Memory vfreed
     - Hashed
     - >= 1 child
     - None (waits unregister)

   * - **GONE_UNUSED**
     - ``freeing_list``
     - QUIESCENT (0 in module)
     - Memory vfreed
     - UNLINKED
     - EMPTY (0)
     - Tasks RCU


6. Interaction Walkthrough: User Kprobe & Aggrprobe
===================================================

Step 1: Optimization Trigger
----------------------------

1. Caller invokes ``register_kprobe(p)``.

2. ``__register_kprobe()`` calls ``try_to_optimize_kprobe(p)``, which calls
   ``optimize_kprobe(ap)``.

3. Under ``kprobe_mutex``, ``optimize_kprobe()`` performs two atomic actions:

   - Sets ``ap->flags |= KPROBE_FLAG_OPTIMIZED``.
   - Adds ``op->list`` onto ``optprobe_gens[cur_gen].optimizing_list``.

4. **Execution Effect**:
   The instruction in text is still ``INT3``. However, when a CPU hits
   ``INT3``, ``setup_singlestep()`` calls ``setup_detour_execution()``.
   Because ``KPROBE_FLAG_OPTIMIZED`` is set, ``setup_detour_execution()``
   updates ``regs->ip`` to point directly to
   ``op->optinsn.insn + TMPL_END_IDX``. The detour trampoline is now actively
   executing handlers before the jump is installed.

Step 2: Binary Optimization (Jump Installation)
-----------------------------------------------

1. The optimizer thread processes the generation via
   ``optprobe_finalize_generation()``.

2. It executes ``arch_optimize_kprobes()`` under ``text_mutex`` and
   ``cpus_read_lock()``, replacing ``INT3`` with a 5-byte relative jump.

3. Removes ``op->list`` from ``optimizing_list`` (now ``NOT_QUEUED``).

4. **Execution Effect**:
   CPUs execute the relative jump natively, bypassing exception traps.

Step 3: Unoptimization & Trampoline Drainage
--------------------------------------------

1. Caller invokes ``disable_kprobe(p)`` or ``unregister_kprobe(p)``.

2. ``__disarm_kprobe(ap)`` calls ``unoptimize_kprobe(ap, false)``, placing
   ``op->list`` onto ``optprobe_gens[cur_gen].unoptimizing_list``.

3. The optimizer dispatches the generation via
   ``optprobe_dispatch_generation()``:

   - Calls ``arch_unoptimize_kprobes()`` under ``text_mutex`` to replace the
     relative jump with an ``INT3`` breakpoint and restore trailing original
     bytes.
   - Clears ``ap->flags &= ~KPROBE_FLAG_OPTIMIZED``.
   - Moves ``op->list`` to ``gen->cooling_list``.
   - Calls ``call_rcu_tasks(&gen->rcu)`` to initiate the Tasks RCU grace
     period.

4. **Execution Effect**:
   Because ``KPROBE_FLAG_OPTIMIZED`` is cleared, subsequent ``INT3`` hits take
   the normal single-step path and will not enter the detour buffer. Preempted
   tasks inside the trampoline continue executing towards the exit.

Step 4: Disarming and Unregistering While Cooling
-------------------------------------------------

1. If a probe is disabled while on ``cooling_list``, ``__disarm_kprobe()``
   calls ``arch_disarm_kprobe(ap)`` immediately (``INT3`` -> original byte).
   This text patch is safe because the jump is already removed.

2. If a probe is unregistered while on ``cooling_list``,
   ``list_del_rcu(&p->list)`` empties ``ap->list``. The aggregator ``ap``
   remains attached to ``cooling_list`` and hashed in ``kprobe_table[]`` to
   prevent premature reclamation by ``__unregister_kprobe_bottom()``.

3. When the Tasks RCU callback fires, ``optprobe_finalize_generation()``
   detects ``kprobe_unused(ap) == true``:

   - Disarms ``INT3`` if not already done.
   - Unlinks ``ap`` from ``kprobe_table[]`` (``hlist_del_init_rcu``).
   - Moves ``op->list`` to ``cur_gen.freeing_list`` to wait for a Standard RCU
     grace period before calling ``free_aggr_kprobe(ap)``.


7. Global & Subsystem Lifecycle Operations
==========================================

7.1 Module Unloading (``kill_kprobe()`` via ``MODULE_STATE_GOING``)
-------------------------------------------------------------------

When a kernel module containing probed instructions is unloaded:

1. **Safety Precondition**:
   The module loader ensures ``module_refcount(mod) == 0``, no CPUs are
   actively executing module code, and no new tasks can enter the module.

2. **Identification**:
   Under ``kprobe_mutex``, ``kprobes_module_callback()`` scans
   ``kprobe_table[]`` for addresses within the module and calls
   ``kill_kprobe(p)`` -> ``kill_optimized_kprobe(p)``.

3. **Queue Cleanup and Text-Poke Bypass**:

   - **OPT_QUEUED**: Removed from ``optimizing_list`` immediately. This
     guarantees the optimizer thread will never attempt to patch a relative
     jump into tearing-down module text.
   - **COOLING_UNUSED**: The probe has no children. It transitions to
     ``GONE_UNUSED``, is unlinked from ``kprobe_table[]`` immediately, and is
     moved to ``cur_gen.freeing_list``. Its detour trampoline is guaranteed
     **QUIESCENT** because no threads can execute in the unloaded module.
   - **Text-Poke Bypass**: ``arch_disarm_kprobe()`` is explicitly skipped.
     Since the module memory is about to be released via ``vfree()``, skipping
     text patching avoids invalid page-table operations or page faults.
   - **Instruction Slot Reclaim**: Single-step and detour instruction slots
     are safely reclaimed immediately.

7.2 Global Optimization Toggle (``debug.kprobes-optimization``)
---------------------------------------------------------------

Jump optimization can be dynamically toggled via sysctl:

1. **Disabling Optimization (``sysctl debug.kprobes-optimization=0``)**:

   - Sets ``kprobes_allow_optimization = false``.
   - Iterates through ``kprobe_table[]`` and calls
     ``unoptimize_kprobe(p, false)``:

     * ``OPTIMIZED`` probes move to ``cur_gen.unoptimizing_list``.
     * ``OPT_QUEUED`` probes are dequeued and revert to ``ARMED_INT3``.

   - Invokes ``wait_for_kprobe_optimizer_locked()`` to flush all generations.
   - **Guarantee**: When the sysctl write returns, zero jump instructions
     remain in kernel text, zero tasks execute in detour trampolines, and all
     probes function as standard breakpoints.

2. **Re-enabling Optimization (``sysctl debug.kprobes-optimization=1``)**:

   - Sets ``kprobes_allow_optimization = true``.
   - Iterates through ``kprobe_table[]`` and calls ``optimize_kprobe(p)`` on
     all enabled probes, re-queuing them into ``cur_gen.optimizing_list``.

7.3 Global Disarm Toggle (``/sys/kernel/debug/kprobes/enabled``)
----------------------------------------------------------------

All kprobes can be globally suppressed via debugfs:

1. **Disarming (``echo 0 > /sys/kernel/debug/kprobes/enabled``)**:

   - Sets ``kprobes_all_disarmed = true``.
   - Calls ``disarm_kprobe(p, false)`` on every probe.
   - Because ``kprobes_all_disarmed`` is true, ``force`` is set to true:

     * ``force_unoptimize_kprobe(op)`` synchronously restores original bytes
       under ``text_mutex``.
     * ``arch_disarm_kprobe(p)`` synchronously removes the breakpoint.

   - Calls ``wait_for_kprobe_optimizer_locked()`` to drain Tasks RCU.
   - **Guarantee**: All kernel text modifications are completely undone, and
     the kernel runs with 0% probe overhead.

2. **Re-arming (``echo 1 > /sys/kernel/debug/kprobes/enabled``)**:

   - Sets ``kprobes_all_disarmed = false``.
   - Calls ``arm_kprobe(p)`` and ``optimize_kprobe(p)`` on every non-disabled
     probe, re-establishing breakpoints and queuing jump optimizations.


8. Grace Period and Synchronization Distinctions
================================================

The optimizer relies on two distinct RCU grace period mechanisms with different
safety semantics:

1. **Tasks RCU (``call_rcu_tasks()``)**:

   - **Protection Target**: Execution of executable machine code.
   - **Mechanism**: Waits for all tasks running in kernel space (excluding idle
     loops and voluntary schedule points) to complete their current execution
     quantum.
   - **Application**: Drains preempted tasks running inside the ``optinsn``
     detour trampoline buffer or traversing the 5-byte instruction window
     before instruction memory is reclaimed or modified.

2. **Standard RCU (``call_rcu()`` / ``synchronize_rcu()``)**:

   - **Protection Target**: Data structures and pointer dereferences.
   - **Mechanism**: Waits for all CPU read-side critical sections
     (``rcu_read_lock()`` .. ``rcu_read_unlock()``) to complete.
   - **Application**: Protects traversals of the global ``kprobe_table[]``
     hash table and the child user kprobe list (``ap->list``) against
     concurrent unlinking and memory reclamation (``free_aggr_kprobe()``).
