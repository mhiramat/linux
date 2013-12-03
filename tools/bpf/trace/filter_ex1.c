#include <linux/bpf.h>

struct bpf_insn bpf_insns_filter[] = {
// registers to save R6 R7
// allocate 24 bytes stack
	BPF_INSN_ST_IMM(BPF_W, __fp__, -20, 28524), // *(uint32*)(__fp__, -20)=28524
	BPF_INSN_LD(BPF_DW, R6, R1, 104), // R6=*(uint64*)(R1, 104)
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_ALU_IMM(BPF_ADD, R1, 32), // R1 += 32
	BPF_INSN_CALL(1), // R0=bpf_load_pointer();
	BPF_INSN_ALU(BPF_MOV, R7, R0), // R7 = R0
	BPF_INSN_ALU_IMM(BPF_MOV, R3, 2), // R3 = 2
	BPF_INSN_ALU(BPF_MOV, R2, __fp__), // R2 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R2, -20), // R2 += -20
	BPF_INSN_ALU(BPF_MOV, R1, R7), // R1 = R7
	BPF_INSN_CALL(18), // R0=bpf_memcmp();
	BPF_INSN_JUMP_IMM(BPF_JNE, R0, 0, 11), // if (R0 != 0) goto LabelL5
	BPF_INSN_ST_IMM(BPF_W, __fp__, -16, 543320947), // *(uint32*)(__fp__, -16)=543320947
	BPF_INSN_ST_IMM(BPF_W, __fp__, -12, 1679847461), // *(uint32*)(__fp__, -12)=1679847461
	BPF_INSN_ST_IMM(BPF_W, __fp__, -8, 622884453), // *(uint32*)(__fp__, -8)=622884453
	BPF_INSN_ST_IMM(BPF_W, __fp__, -4, 663664), // *(uint32*)(__fp__, -4)=663664
	BPF_INSN_ALU_IMM(BPF_MOV, R5, 0), // R5 = 0
	BPF_INSN_ALU(BPF_MOV, R4, R7), // R4 = R7
	BPF_INSN_ALU(BPF_MOV, R3, R6), // R3 = R6
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 16), // R2 = 16
	BPF_INSN_ALU(BPF_MOV, R1, __fp__), // R1 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R1, -16), // R1 += -16
	BPF_INSN_CALL(29), // (void)bpf_trace_printk();
//LabelL5:
	BPF_INSN_RET(), // return void
};

const char func_strtab[46] = "\0bpf_load_pointer\0bpf_memcmp\0bpf_trace_printk";

int main()
{
	char header[4] = "bpf";

	int insn_size = sizeof(bpf_insns_filter);
	int htab_size = 0;
	int strtab_size = sizeof(func_strtab);

	write(1, header, 4);
	write(1, &insn_size, 4);
	write(1, &htab_size, 4);
	write(1, &strtab_size, 4);

	write(1, bpf_insns_filter, insn_size);
	write(1, func_strtab, strtab_size);
	return 0;
}

