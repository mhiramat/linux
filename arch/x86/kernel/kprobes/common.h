/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_KERNEL_KPROBES_COMMON_H
#define __X86_KERNEL_KPROBES_COMMON_H

/* Kprobes and Optprobes common header */

#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/insn.h>

#ifdef CONFIG_X86_64

#define SAVE_REGS_STRING			\
	/* Skip cs, ip, orig_ax. */		\
	"	subq $24, %rsp\n"		\
	"	pushq %rdi\n"			\
	"	pushq %rsi\n"			\
	"	pushq %rdx\n"			\
	"	pushq %rcx\n"			\
	"	pushq %rax\n"			\
	"	pushq %r8\n"			\
	"	pushq %r9\n"			\
	"	pushq %r10\n"			\
	"	pushq %r11\n"			\
	"	pushq %rbx\n"			\
	"	pushq %rbp\n"			\
	"	pushq %r12\n"			\
	"	pushq %r13\n"			\
	"	pushq %r14\n"			\
	"	pushq %r15\n"			\
	ENCODE_FRAME_POINTER

#define RESTORE_REGS_STRING			\
	"	popq %r15\n"			\
	"	popq %r14\n"			\
	"	popq %r13\n"			\
	"	popq %r12\n"			\
	"	popq %rbp\n"			\
	"	popq %rbx\n"			\
	"	popq %r11\n"			\
	"	popq %r10\n"			\
	"	popq %r9\n"			\
	"	popq %r8\n"			\
	"	popq %rax\n"			\
	"	popq %rcx\n"			\
	"	popq %rdx\n"			\
	"	popq %rsi\n"			\
	"	popq %rdi\n"			\
	/* Skip orig_ax, ip, cs */		\
	"	addq $24, %rsp\n"
#else

#define SAVE_REGS_STRING			\
	/* Skip cs, ip, orig_ax and gs. */	\
	"	subl $4*4, %esp\n"		\
	"	pushl %fs\n"			\
	"	pushl %es\n"			\
	"	pushl %ds\n"			\
	"	pushl %eax\n"			\
	"	pushl %ebp\n"			\
	"	pushl %edi\n"			\
	"	pushl %esi\n"			\
	"	pushl %edx\n"			\
	"	pushl %ecx\n"			\
	"	pushl %ebx\n"			\
	ENCODE_FRAME_POINTER

#define RESTORE_REGS_STRING			\
	"	popl %ebx\n"			\
	"	popl %ecx\n"			\
	"	popl %edx\n"			\
	"	popl %esi\n"			\
	"	popl %edi\n"			\
	"	popl %ebp\n"			\
	"	popl %eax\n"			\
	/* Skip ds, es, fs, gs, orig_ax, ip, and cs. */\
	"	addl $7*4, %esp\n"
#endif

/* Ensure if the instruction can be boostable */
extern int can_boost(struct insn *insn, void *orig_addr);
/* Recover instruction if given address is probed */
extern unsigned long recover_probed_instruction(kprobe_opcode_t *buf,
					 unsigned long addr);
/*
 * Copy an instruction and adjust the displacement if the instruction
 * uses the %rip-relative addressing mode.
 */
extern int __copy_instruction(u8 *dest, u8 *src, u8 *real, struct insn *insn);

/* Generate a relative-jump/call instruction */
extern void synthesize_reljump(void *dest, void *from, void *to);
extern void synthesize_relcall(void *dest, void *from, void *to);

/* Return the jump target address or 0 */
static inline unsigned long insn_get_branch_addr(struct insn *insn)
{
	switch (insn->opcode.bytes[0]) {
	case 0xe0:	/* loopne */
	case 0xe1:	/* loope */
	case 0xe2:	/* loop */
	case 0xe3:	/* Jcxz */
	case 0xe9:	/* JMP.d32 */
	case 0xeb:	/* JMP.d8 */
		break;
	case 0x0f:
		if ((insn->opcode.bytes[1] & 0xf0) == 0x80) /* Jcc.d32 */
			break;
		return 0;
	case 0x70 ... 0x7f: /* Jcc.d8 */
		break;

	default:
		return 0;
	}
	return (unsigned long)insn->next_byte + insn->immediate.value;
}

static inline void __decode_insn(struct insn *insn, kprobe_opcode_t *buf,
				 unsigned long addr)
{
	unsigned long recovered_insn;

	/*
	 * Check if the instruction has been modified by another
	 * kprobe, in which case we replace the breakpoint by the
	 * original instruction in our buffer.
	 * Also, jump optimization will change the breakpoint to
	 * relative-jump. Since the relative-jump itself is
	 * normally used, we just go through if there is no kprobe.
	 */
	recovered_insn = recover_probed_instruction(buf, addr);
	if (!recovered_insn ||
	    insn_decode_kernel(insn, (void *)recovered_insn) < 0) {
		insn->kaddr = NULL;
	} else {
		/* Recover address */
		insn->kaddr = (void *)addr;
		insn->next_byte = (void *)(addr + insn->length);
	}
}

/* Iterate instructions in [saddr, eaddr), insn->next_byte is loop cursor. */
#define for_each_insn(insn, saddr, eaddr, buf)				\
	for (__decode_insn(insn, buf, saddr);				\
	     (insn)->kaddr && (unsigned long)(insn)->next_byte < eaddr;	\
	     __decode_insn(insn, buf, (unsigned long)(insn)->next_byte))

int every_insn_in_func(unsigned long faddr,
		       int (*callback)(struct insn *, void *),
		       void *data);

#ifdef	CONFIG_OPTPROBES
extern int setup_detour_execution(struct kprobe *p, struct pt_regs *regs, int reenter);
extern unsigned long __recover_optprobed_insn(kprobe_opcode_t *buf, unsigned long addr);
#else	/* !CONFIG_OPTPROBES */
static inline int setup_detour_execution(struct kprobe *p, struct pt_regs *regs, int reenter)
{
	return 0;
}
static inline unsigned long __recover_optprobed_insn(kprobe_opcode_t *buf, unsigned long addr)
{
	return addr;
}
#endif

#endif
