#ifndef __X86_DISASM_H__
#define __X86_DISASM_H__
#include <asm/insn.h>

/* Mnemonic format table lookup routines */
extern const char *get_mnemonic_format(struct insn *insn, const char **grp);
extern const char *get_prefix_name(struct insn *insn);

#define DISASM_STR_LEN 128

/* Disassemble options */
#define DISASM_PR_ADDR	1	/* Print address */
#define DISASM_PR_RAW	2	/* Print raw code */
#define DISASM_PR_ALL	(DISASM_PR_ADDR | DISASM_PR_RAW)

/* Disassemble given decoded instruction */
extern int disassemble(char *buf, size_t len, struct insn *insn);

/* Put disassembled code with raw code and address into buffer */
extern int snprint_assembly(char *buf, size_t len, struct insn *insn, int opts);

#endif	/*__X86_DISASM_H__*/
