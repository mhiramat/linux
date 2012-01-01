#ifndef __X86_DISASM_H__
#define __X86_DISASM_H__
#include <asm/insn.h>

/* Mnemonic format table lookup routines */
extern const char *get_mnemonic_format(struct insn *insn, const char **grp);
extern const char *get_prefix_name(struct insn *insn);

/* Disassemble an instruction */
extern int disassemble(struct insn *insn, char *buf, size_t len);

#endif	/*__X86_DISASM_H__*/
