#ifndef __X86_DISASM_H__
#define __X86_DISASM_H__
#include <asm/insn.h>

/* Consumed the last prefix for variant */
#define DISASM_HINT_VARIANT 1

/* Mnemonic format table lookup routines */
extern const char *get_mnemonic_format(struct insn *insn, const char **grp, int *hint);
extern const char *get_prefix_name(insn_byte_t prefix, int hint);

#define DISASM_STR_LEN	128

#define DISASM_SYNTAX_INTEL	0
#define DISASM_SYNTAX_ATT	1

/* Disassemble given decoded instruction */
extern int disassemble(char *buf, size_t len, struct insn *insn, int syntax);

#endif	/*__X86_DISASM_H__*/
