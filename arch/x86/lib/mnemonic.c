#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/insn.h>
#include <asm/disasm.h>

/* Define mnemonic lookup table */
#include "mnemonic-tables.c"

static const char *__get_variant(const char *fmt, char *pfx)
{
	const char *p;

	p = strstr(fmt, pfx);
	if (!p)
		return fmt;
	return strchr(p, ':') + 1;
}

static const char *__get_variant_rm(const char *fmt, struct insn *insn)
{
	int rm = X86_MODRM_RM(insn->modrm.bytes[0]);
	char buf[5] = {
		[0] = '%',
		[1] = (rm & 0x4) ? '1' : '0',
		[2] = (rm & 0x2) ? '1' : '0',
		[3] = (rm & 0x1) ? '1' : '0',
		[4] = '\0'};
	return __get_variant(fmt, buf);
}

static const char *get_variant(const char *fmt, struct insn *insn)
{
	char *p, *q;

	if (!fmt)
		return NULL;

	p = strchr(fmt, '%');
	if (p) {
		if (insn->modrm.nbytes &&
		    X86_MODRM_MOD(insn->modrm.bytes[0]) == 3) {
			q = strstr(fmt, "%11B");
			if (q) {
				fmt = __get_variant_rm(q, insn);
				if (q == fmt)
					fmt = strchr(q, ':') + 1;
				goto out;
			}
		}
		if (strchr("wdq", p[1])) {
			if (insn->opnd_bytes == 2)
				fmt = __get_variant(fmt, "%w");
			else if (insn->opnd_bytes == 4)
				fmt = __get_variant(fmt, "%d");
			else if (insn->opnd_bytes == 8)
				fmt = __get_variant(fmt, "%q");
			goto out;
		}
		if (insn->x86_64) {
			p = strstr(fmt, "%e");
			if (p && *(p + 2) == ':')
				fmt = p + 3;
		} else if (fmt[0] == '%' && fmt[1] == 'e')
			fmt = NULL;
	}
out:
	if (fmt && fmt[0] == 'v' && inat_accept_vex(insn->attr) && !insn_is_avx(insn))
		fmt++;	/* Skip v prefix if it is not AVX format */
	return fmt;
}

const char *get_mnemonic_format(struct insn *insn, const char **grp, int *hint)
{
	insn_attr_t attr;
	const char *ret = NULL;
	const char * const *table;
	int n, m;
	insn_byte_t idx, *bytes = insn->opcode.bytes;

	if (!insn_complete(insn))
		goto fail;	/* Decode it first! */

	idx = *bytes;
	if (insn_is_avx(insn)) {
		/* Lookup AVX instruction */
		n = insn_vex_m_bits(insn);
		if (n == 0 || n > 3)	/* out of range */
			goto fail;
		m = insn_vex_p_bits(insn);
		attr = inat_get_avx_attribute(idx, n, 0);
		if (!inat_is_group(attr) && m)
			table = mnemonic_escape_tables[n][m];
		else
			table = mnemonic_escape_tables[n][0];
	} else {
		/* Lookup normal instruction */
		attr = inat_get_opcode_attribute(idx);
		m = insn_last_prefix_id(insn);
		/*TODO use (inat_has_variant(attr))*/
		table = mnemonic_primary_tables[m];
		if (!table || !table[idx])
			table = mnemonic_primary_tables[0];
		else
			*hint |= DISASM_HINT_VARIANT;
		/* Solve escapes */
		while (inat_is_escape(attr)) {
			n = inat_escape_id(attr);
			idx = *++bytes;
			attr = inat_get_escape_attribute(idx, 0, attr);
			if (inat_has_variant(attr)) {
				table = mnemonic_escape_tables[n][m];
				*hint |= DISASM_HINT_VARIANT;
			} else
				table = mnemonic_escape_tables[n][0];
		}
	}
	if (table)
		ret = get_variant(table[idx], insn);

	/* Solve groups */
	if (grp && inat_is_group(attr)) {
		n = inat_group_id(attr);
		idx = insn->modrm.bytes[0];
		attr = inat_get_group_attribute(idx, 0, attr);
		if (inat_has_variant(attr)) {
			*hint |= DISASM_HINT_VARIANT;
			table = mnemonic_group_tables[n][m];
		} else
			table = mnemonic_group_tables[n][0];
		idx = X86_MODRM_REG(idx);
		*grp = get_variant(table[idx], insn);
	}
	return ret;

fail:
	return NULL;
}

const char *get_prefix_name(insn_byte_t prefix, int hint)
{
	insn_attr_t attr;

	attr = inat_get_opcode_attribute(prefix);
	attr &= INAT_PFX_MASK;
	if ((hint & DISASM_HINT_VARIANT) && inat_last_prefix_id(attr) != 0)
		return NULL;
	if (attr == INAT_PFX_REPE || attr == INAT_PFX_REPNE ||
	    attr == INAT_PFX_LOCK)
		return mnemonic_primary_table[prefix];

	return NULL;
}
