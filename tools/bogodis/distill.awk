#!/bin/awk -f
# Usage: objdump -d a.out | awk -f distill.awk | ./test_get_len
# Distills the disassembly as follows:
# - Removes all lines except the disassembled instructions.
# - For instructions that exceed 1 line (7 bytes), crams all the hex bytes
# into a single line.
# - Remove bad(or prefix only) instructions

BEGIN {
	prev_addr = ""
	prev_hex = ""
	prev_mnemonic = ""
	bad_expr = "(\\(bad\\)|^rex|^\.byte|^repz|^repnz|^lock$|^es$|^cs$|^ss$|^ds$|^fs$|^gs$|^data(16|32)$|^addr(16|32|64))"
	fwait_expr = "^9b "
	fwait_str="9b\tfwait"
}

/^ *[0-9a-f]+ <[^>]*>:/ {
	# Symbol entry
	#printf("%s%s\n", $2, $1)
}

/^ *[0-9a-f]+:/ {
	if (index($0, "#"))
		split($0, real, "#")
	else
		split($0, real, "<")
	if (split(real[1], field, "\t") < 3) {
		# This is a continuation of the same insn.
		prev_hex = prev_hex field[2]
	} else {
		# Skip bad instructions
		if (match(prev_mnemonic, bad_expr))
			prev_addr = ""
		gsub("repz", "rep", prev_mnemonic)
		gsub("movabs", "mov", prev_mnemonic)
		gsub("xchg[\t ]*[er]*ax,[er]*ax", "nop", prev_mnemonic)
		gsub("data(32|16)", "", prev_mnemonic)
		gsub("addr(64|32|16)", "", prev_mnemonic)
		gsub("OWORD", "XMMWORD", prev_mnemonic)
		# Split fwait from other f* instructions
		if (match(prev_hex, fwait_expr) && prev_mnemonic != "fwait") {
			printf "%s\t%s\n", prev_addr, fwait_str
			sub(fwait_expr, "", prev_hex)
		}
		if (prev_addr != "")
			printf "%s\t%s\t%s\n", prev_addr, prev_hex, prev_mnemonic
		prev_addr = field[1]
		prev_hex = field[2]
		prev_mnemonic = field[3]
	}
}

END {
	if (prev_addr != "")
		printf "%s\t%s\t%s\n", prev_addr, prev_hex, prev_mnemonic
}
