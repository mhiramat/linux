/*
 * Copyright (C) 2016 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_SECTIONS_H
#define __ASM_SECTIONS_H

#include <asm-generic/sections.h>

extern char __alt_instructions[], __alt_instructions_end[];
extern char __exception_text_start[], __exception_text_end[];
extern char __hibernate_exit_text_start[], __hibernate_exit_text_end[];
extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
extern char __hyp_text_start[], __hyp_text_end[];
extern char __idmap_text_start[], __idmap_text_end[];
extern char __initdata_begin[], __initdata_end[];
extern char __inittext_begin[], __inittext_end[];
extern char __irqentry_text_start[], __irqentry_text_end[];
extern char __mmuoff_data_start[], __mmuoff_data_end[];

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

/**
 * in_entry_text - check if an address is in entry_text
 * @addr: virtual address to be checked
 *
 * Returns: true if the address specified by @addr is in the entry_text,
 * false otherwise.
 */
static inline bool in_entry_text(unsigned long addr)
{
	return memory_contains(__entry_text_start, __entry_text_end,
			       (void *)addr, 0);
}
#endif /* __ASM_SECTIONS_H */
