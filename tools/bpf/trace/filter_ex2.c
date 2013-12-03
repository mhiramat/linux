#include <linux/bpf.h>

struct bpf_insn bpf_insns_filter[] = {
// registers to save R6 R7
// allocate 32 bytes stack
	BPF_INSN_ALU(BPF_MOV, R6, R1), // R6 = R1
	BPF_INSN_ST_IMM(BPF_DW, __fp__, -32, 0), // *(uint64*)(__fp__, -32)=0
	BPF_INSN_LD(BPF_DW, R1, R6, 104), // R1=*(uint64*)(R6, 104)
	BPF_INSN_ALU_IMM(BPF_ADD, R1, 32), // R1 += 32
	BPF_INSN_CALL(1), // R0=bpf_load_pointer();
	BPF_INSN_ALU(BPF_MOV, R7, R0), // R7 = R0
	BPF_INSN_ST(BPF_DW, __fp__, -32, R7), // *(uint64*)(__fp__, -32)=R7
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -32), // R3 += -32
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(18), // R0=bpf_table_lookup();
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 18), // if (R0 == 0) goto LabelL2
	BPF_INSN_ALU_IMM(BPF_MOV, R1, 1), // R1 = 1
	BPF_INSN_XADD(BPF_DW, R0, 0, R1), // atomic (*(uint64*)R0, 0) += R1
	BPF_INSN_LD(BPF_DW, R1, R0, 0), // R1=*(uint64*)(R0, 0)
	BPF_INSN_ALU_IMM(BPF_MOD, R1, 10000), // R1=((uint64)R1)%((uint64)10000)
	BPF_INSN_JUMP_IMM(BPF_JNE, R1, 0, 21), // if (R1 != 0) goto LabelL6
	BPF_INSN_ST_IMM(BPF_W, __fp__, -24, 544630116), // *(uint32*)(__fp__, -24)=544630116
	BPF_INSN_ST_IMM(BPF_W, __fp__, -20, 538996773), // *(uint32*)(__fp__, -20)=538996773
	BPF_INSN_ST_IMM(BPF_W, __fp__, -16, 1601465200), // *(uint32*)(__fp__, -16)=1601465200
	BPF_INSN_ST_IMM(BPF_W, __fp__, -12, 544501347), // *(uint32*)(__fp__, -12)=544501347
	BPF_INSN_ST_IMM(BPF_W, __fp__, -8, 680997), // *(uint32*)(__fp__, -8)=680997
	BPF_INSN_ALU_IMM(BPF_MOV, R5, 0), // R5 = 0
	BPF_INSN_LD(BPF_DW, R4, R0, 0), // R4=*(uint64*)(R0, 0)
	BPF_INSN_ALU(BPF_MOV, R3, R7), // R3 = R7
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 20), // R2 = 20
	BPF_INSN_ALU(BPF_MOV, R1, __fp__), // R1 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R1, -24), // R1 += -24
	BPF_INSN_CALL(35), // (void)bpf_trace_printk();
	BPF_INSN_JUMP(BPF_JA, 0, 0, 8), // goto LabelL6
//LabelL2:
	BPF_INSN_ST_IMM(BPF_DW, __fp__, -24, 0), // *(uint64*)(__fp__, -24)=0
	BPF_INSN_ALU(BPF_MOV, R4, __fp__), // R4 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R4, -24), // R4 += -24
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -32), // R3 += -32
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(52), // R0=bpf_table_update();
//LabelL6:
	BPF_INSN_RET(), // return void
};

struct bpf_table bpf_filter_tables[] = {
	{BPF_TABLE_HASH, 8, 8, 4096, 0}
};

const char func_strtab[69] = "\0bpf_load_pointer\0bpf_table_lookup\0bpf_trace_printk\0bpf_table_update";

int main()
{
	char header[4] = "bpf";

	int insn_size = sizeof(bpf_insns_filter);
	int htab_size = sizeof(bpf_filter_tables);
	int strtab_size = sizeof(func_strtab);

	write(1, header, 4);
	write(1, &insn_size, 4);
	write(1, &htab_size, 4);
	write(1, &strtab_size, 4);

	write(1, bpf_insns_filter, insn_size);
	write(1, bpf_filter_tables, htab_size);
	write(1, func_strtab, strtab_size);
	return 0;
}

