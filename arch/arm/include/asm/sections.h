#ifndef _ASM_ARM_SECTIONS_H
#define _ASM_ARM_SECTIONS_H

#include <asm-generic/sections.h>

extern char _exiprom[];
extern char __exception_text_start[], __exception_text_end[];

/**
 * in_exception_text - check if an address is in exception_text or
 *			irqentry_text
 * @addr: virtual address to be checked
 *
 * Returns: true if the address specified by @addr is in the exception_text or
 * irqentry_text, false otherwise.
 */
static inline bool in_exception_text(unsigned long addr)
{
	return memory_contains(__exception_text_start, __exception_text_end,
			       (void *)addr, 0) ||
		memory_contains(__irqentry_text_start, __irqentry_text_end,
				(void *)addr, 0);
}

#endif	/* _ASM_ARM_SECTIONS_H */
