#!/bin/awk -f
# gen-insn-mnemonic-x86.awk: X86 Instruction mnemonic table generator
# Written by Masami Hiramatsu <masami.hiramatsu@gmail.com>
#
# Usage: awk -f gen-insn-mnemonic-x86.awk x86-opcode-map.txt > mnemonic-tables.c

# Awk implementation sanity check
function check_awk_implement() {
	if (sprintf("%x", 0) != "0")
		return "Your awk has a printf-format problem."
	return ""
}

# Clear working vars
function clear_vars() {
	delete table
	delete lptable1
	delete lptable2
	delete lptable3
	eid = -1 # escape id
	gid = -1 # group id
	aid = -1 # AVX id
	tname = ""
}

BEGIN {
	# Implementation error checking
	awkchecked = check_awk_implement()
	if (awkchecked != "") {
		print "Error: " awkchecked > "/dev/stderr"
		print "Please try to use gawk." > "/dev/stderr"
		exit 1
	}

	# Setup generating tables
	print "/* x86 opcode map generated from x86-opcode-map.txt */"
	print "/* Do not change this code. */\n"
	ggid = 1
	geid = 1
	gaid = 0
	delete etable
	delete gtable
	delete atable

	opnd_expr = "^[A-Za-z/]"
	ext_expr = "^\\("
	sep_expr = "^\\|$"
	group_expr = "^Grp[0-9A-Za-z]+"
	regs_expr = "^[ABCDEFGSR][0-9A-Z]"
	vregs_expr = "^[re][0-9A-Z]"

	only64_expr = "\\(o64\\)"
	lprefix1_expr = "\\(66\\)"
	lprefix2_expr = "\\(F3\\)"
	lprefix3_expr = "\\(F2\\)"
	max_lprefix = 4

	prefix_expr = "\\(Prefix\\)"
	imm_expr = "^[IJAO][a-z]"
	clear_vars()
}

function semantic_error(msg) {
	print "Semantic error at " NR ": " msg > "/dev/stderr"
	exit 1
}

function debug(msg) {
	print "DEBUG: " msg
}

function array_size(arr,   i,c) {
	c = 0
	for (i in arr)
		c++
	return c
}

/^Table:/ {
	print "/* " $0 " */"
	if (tname != "")
		semantic_error("Hit Table: before EndTable:.");
}

/^Referrer:/ {
	if (NF != 1) {
		# escape opcode table
		ref = ""
		for (i = 2; i <= NF; i++)
			ref = ref $i
		eid = escape[ref]
		tname = sprintf("mnemonic_escape_table_%d", eid)
	}
}

/^AVXcode:/ {
	if (NF != 1) {
		# AVX/escape opcode table
		aid = $2
		if (gaid <= aid)
			gaid = aid + 1
		if (tname == "")	# AVX only opcode table
			tname = sprintf("mnemonic_avx_table_%d", $2)
	}
	if (aid == -1 && eid == -1)	# primary opcode table
		tname = "mnemonic_primary_table"
}

/^GrpTable:/ {
	print "/* " $0 " */"
	if (!($2 in group))
		semantic_error("No group: " $2 )
	gid = group[$2]
	tname = "mnemonic_group_table_" gid
}

function print_table(tbl,name,fmt,n)
{
	print "const char *" name " = {"
	for (i = 0; i < n; i++) {
		id = sprintf(fmt, i)
		if (tbl[id])
			print "	[" id "] = " tbl[id] ","
	}
	print "};"
}

/^EndTable/ {
	if (gid != -1) {
		# print group tables
		if (array_size(table) != 0) {
			print_table(table, tname "[INAT_GROUP_TABLE_SIZE]",
				    "0x%x", 8)
			gtable[gid,0] = tname
		}
		if (array_size(lptable1) != 0) {
			print_table(lptable1, tname "_1[INAT_GROUP_TABLE_SIZE]",
				    "0x%x", 8)
			gtable[gid,1] = tname "_1"
		}
		if (array_size(lptable2) != 0) {
			print_table(lptable2, tname "_2[INAT_GROUP_TABLE_SIZE]",
				    "0x%x", 8)
			gtable[gid,2] = tname "_2"
		}
		if (array_size(lptable3) != 0) {
			print_table(lptable3, tname "_3[INAT_GROUP_TABLE_SIZE]",
				    "0x%x", 8)
			gtable[gid,3] = tname "_3"
		}
	} else {
		# print primary/escaped tables
		if (array_size(table) != 0) {
			print_table(table, tname "[INAT_OPCODE_TABLE_SIZE]",
				    "0x%02x", 256)
			etable[eid,0] = tname
			if (aid >= 0)
				atable[aid,0] = tname
		}
		if (array_size(lptable1) != 0) {
			print_table(lptable1,tname "_1[INAT_OPCODE_TABLE_SIZE]",
				    "0x%02x", 256)
			etable[eid,1] = tname "_1"
			if (aid >= 0)
				atable[aid,1] = tname "_1"
		}
		if (array_size(lptable2) != 0) {
			print_table(lptable2,tname "_2[INAT_OPCODE_TABLE_SIZE]",
				    "0x%02x", 256)
			etable[eid,2] = tname "_2"
			if (aid >= 0)
				atable[aid,2] = tname "_2"
		}
		if (array_size(lptable3) != 0) {
			print_table(lptable3,tname "_3[INAT_OPCODE_TABLE_SIZE]",
				    "0x%02x", 256)
			etable[eid,3] = tname "_3"
			if (aid >= 0)
				atable[aid,3] = tname "_3"
		}
	}
	print ""
	clear_vars()
}

function add_flags(old,new) {
	if (old && new)
		return old "\"|\"" new
	else if (old)
		return old
	else
		return new
}

function get_operand(opnd,	i,count,f8,opnds) {
	count = split(opnd, opnds, ",")
	# re-encode registers
	f8 = 0
	for (i = 1; i <= count; i++) {
		if (match(opnds[i], "^r[A-Z][XIP]/r[189]"))
			opnds[i] = "_vgpr"	# GPR encoded in opcode
		else if (match(opnds[i], "^R[A-Z]*/E[A-Z]*/R[0-9]"))
			opnds[i] = "_lgpr"	# 32 or 64 bit GPR encoded in opcode
		else if (match(opnds[i], "^[A-Z][LH]/R[189]")) {
			opnds[i] = "_bgpr"	# 8 bit GPR encoded in opcode
			f8 = 1	# forcibly 8 bit cast
		} else if (match(opnds[i], regs_expr)) {
			if (match(opnds[i], "^[A-Z][LH]"))
				f8 = 1
			opnds[i] = tolower(opnds[i])
		} else if (match(opnds[i], vregs_expr))
			opnds[i] = "_" tolower(opnds[i])
	}

	for (i = count; i > 0; i--) {
		if (f8 == 1 && match(opnds[i],"Ib"))
			opnds[i] = toupper(opnds[i])
		if (i == count)
			opnd = opnds[i]
		else
			opnd = opnd "," opnds[i]
	}
	return opnd
}

/^[0-9a-f]+\:/ {
	if (NR == 1)
		next
	# get index
	idx = "0x" substr($1, 1, index($1,":") - 1)
	if (idx in table)
		semantic_error("Redefine " idx " in " tname)

	# check if escaped opcode
	if ("escape" == $2) {
		if ($3 != "#")
			semantic_error("No escaped name")
		ref = ""
		for (i = 4; i <= NF; i++)
			ref = ref $i
		if (ref in escape)
			semantic_error("Redefine escape (" ref ")")
		escape[ref] = geid
		geid++
		#table[idx] = "INAT_MAKE_ESCAPE(" escape[ref] ")"
		table[idx] = "\"Escape_" escape[ref] "\""
		next
	}

	variant = null
	# converts
	i = 2
	while (i <= NF) {
		opcode = $(i++)
		ext = null
		flags = null
		opnd = null
		pfx = ""
		# parse one opcode
		if (match($i, opnd_expr))
			opnd = get_operand($(i++))
		if (match($i, ext_expr))
			ext = $(i++)
		if (match($i, sep_expr))
			i++
		else if (i < NF)
			semantic_error($i " is not a separator")

		# check if group opcode
		if (match(opcode, group_expr)) {
			if (!(opcode in group)) {
				group[opcode] = ggid
				ggid++
			}
		}

		# opcode to lower characters
		opcode = tolower(opcode)
		if (index(opcode, "/"))
			opcode = substr(opcode, 0, index(opcode, "/") - 1)
		# remove near/far postfix
		if (match(opcode, "^jmp.*"))
			opcode = "jmp"
		if (match(opcode, "^call.*"))
			opcode = "call"
		if (match(opcode, "^ret.*"))
			opcode = "ret"
		# chose mnemonic for objdump compatibility
		if (opcode == "jnb") opcode = "jae"
		if (opcode == "jz") opcode = "je"
		if (opcode == "jnz") opcode = "jne"
		if (opcode == "jnbe") opcode = "ja"
		if (opcode == "jnl") opcode = "jge"
		if (opcode == "jnle") opcode = "jg"

		# special cases - opcode depends on operand-size
		if (opcode == "cbw")	# cbw/cwde/cdqe
			opcode = "%w:cbw|%d:cwde|%q:cdqe"
		if (opcode == "cwd")	# cwd/cdq/cqo
			opcode = "%w:cwd|%d:cdq|%q:cqo"

		# additional flags
		if (match(ext, only64_expr))
			pfx = "%6:"

		if (length(opnd) != 0)
			flags = "\"" pfx opcode " " opnd "\""
		else
			flags = "\"" pfx opcode "\""

		if (length(flags) == 0)
			continue
		# check if last prefix
		if (match(ext, lprefix1_expr)) {
			lptable1[idx] = add_flags(lptable1[idx], flags)
		} else if (match(ext, lprefix2_expr)) {
			lptable2[idx] = add_flags(lptable2[idx], flags)
		} else if (match(ext, lprefix3_expr)) {
			lptable3[idx] = add_flags(lptable3[idx], flags)
		} else {
			table[idx] = add_flags(table[idx], flags)
		}
	}
}

END {
	if (awkchecked != "")
		exit 1
	# print primary opcode map's array
	print "/* Primary opcode map array */"
	print "const char * const *mnemonic_primary_tables[INAT_LSTPFX_MAX + 1] = {"
	for (j = 0; j < max_lprefix; j++)
		if (etable[-1,j])
			print "	["j"] = "etable[-1,j]","
	print "};\n"
	# print escape opcode map's array
	print "/* Escape opcode map array */"
	print "const char * const *mnemonic_escape_tables[INAT_ESC_MAX + 1]" \
	      "[INAT_LSTPFX_MAX + 1] = {"
	for (i = 0; i < geid; i++)
		for (j = 0; j < max_lprefix; j++)
			if (etable[i,j])
				print "	["i"]["j"] = "etable[i,j]","
	print "};\n"
	# print group opcode map's array
	print "/* Group opcode map array */"
	print "const char * const *mnemonic_group_tables[INAT_GRP_MAX + 1]"\
	      "[INAT_LSTPFX_MAX + 1] = {"
	for (i = 0; i < ggid; i++)
		for (j = 0; j < max_lprefix; j++)
			if (gtable[i,j])
				print "	["i"]["j"] = "gtable[i,j]","
	print "};\n"
	# print AVX opcode map's array
	print "/* AVX opcode map array */"
	print "const char * const *mnemonic_avx_tables[X86_VEX_M_MAX + 1]"\
	      "[INAT_LSTPFX_MAX + 1] = {"
	for (i = 0; i < gaid; i++)
		for (j = 0; j < max_lprefix; j++)
			if (atable[i,j])
				print "	["i"]["j"] = "atable[i,j]","
	print "};"
}

