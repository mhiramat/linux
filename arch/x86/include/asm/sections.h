#ifndef _ASM_X86_SECTIONS_H
#define _ASM_X86_SECTIONS_H

#include <asm-generic/sections.h>
#include <asm/extable.h>

extern char __brk_base[], __brk_limit[];
extern struct exception_table_entry __stop___ex_table[];

#if defined(CONFIG_X86_64)
extern char __end_rodata_hpage_align[];
#endif

/**
 * in_entry_text - check if an address is in entry_text or irqentry_text
 * @addr: virtual address to be checked
 *
 * Returns: true if the address specified by @addr is in the entry_text or
 * irqentry_text, false otherwise.
 */
static inline bool in_entry_text(unsigned long addr)
{
	return memory_contains(__entry_text_start, __entry_text_end,
			       (void *)addr, 0) ||
		memory_contains(__irqentry_text_start, __irqentry_text_end,
				(void *)addr, 0);
}

#endif	/* _ASM_X86_SECTIONS_H */
