#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/insn.h>
#include <asm/disasm.h>

/* Define mnemonic lookup table */
#include "mnemonic-tables.c"

static const char *get_variant(const char *fmt, struct insn *insn)
{
	const char *p;

	if (!fmt)
		goto out;

	if (insn->x86_64) {
		p = strstr(fmt, "%6");
		if (!p)
			goto out;
		fmt = strchr(p, ':') + 1;
	} else if (strstr(fmt, "%6") == fmt)
		fmt = NULL;
out:
	return fmt;
}

const char *get_mnemonic_format(struct insn *insn, const char **grp)
{
	insn_attr_t attr;
	const char *ret = NULL;
	const char * const *table;
	int n, m;
	insn_byte_t idx, *bytes = insn->opcode.bytes;

	if (!insn_complete(insn))
		goto fail;	/* Decode it first! */

	if (insn_is_avx(insn)) {
		/* Lookup AVX instruction */
		goto fail;
	} else {
		/* Lookup normal instruction */
		idx = *bytes;
		attr = inat_get_opcode_attribute(idx);
		m = insn_last_prefix_id(insn);
		/*TODO use (inat_has_variant(attr))*/
		table = mnemonic_primary_tables[m];
		if (!table || !table[idx])
			table = mnemonic_primary_tables[0];
		/* Solve escapes */
		while (inat_is_escape(attr)) {
			n = inat_escape_id(attr);
			idx = *++bytes;
			attr = inat_get_escape_attribute(idx, 0, attr);
			if (inat_has_variant(attr))
				table = mnemonic_escape_tables[n][m];
			else
				table = mnemonic_escape_tables[n][0];
		}
		if (table)
			ret = get_variant(table[idx], insn);

		/* Solve groups */
		if (grp && inat_is_group(attr)) {
			n = inat_group_id(attr);
			idx = insn->modrm.bytes[0];
			attr = inat_get_group_attribute(idx, 0, attr);
			if (inat_has_variant(attr))
				table = mnemonic_group_tables[n][m];
			else
				table = mnemonic_group_tables[n][0];
			idx = X86_MODRM_REG(idx);
			*grp = get_variant(table[idx], insn);
		}
	}
	return ret;

fail:
	return NULL;
}

const char *get_prefix_name(struct insn *insn)
{
	int i = 0;
	insn_attr_t attr;

	for (i = 0; i < insn->prefixes.nbytes; i++) {
		attr = inat_get_opcode_attribute(insn->prefixes.bytes[i]);
		attr &= INAT_PFX_MASK;
		if (attr == INAT_PFX_REPE ||
		    attr == INAT_PFX_REPNE ||
		    attr == INAT_PFX_LOCK)
			return mnemonic_primary_table[insn->prefixes.bytes[i]];
	}
	return NULL;
}
