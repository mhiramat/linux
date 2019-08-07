// SPDX-License-Identifier: GPL-2.0
/* Architecture specific callbacks */
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/skc.h>

#include <asm/setup.h>

__initdata u64 initial_skc;
__initdata u32 initial_skc_len;

void __init add_skc(u64 data, u32 len)
{
	initial_skc = data + offsetof(struct setup_data, data);
	initial_skc_len = len - sizeof(struct setup_data);
}

void __init x86_skc_init(void)
{
	u32 size;
	char *data, *copy;

	if (!initial_skc)
		return;

	data = early_memremap(initial_skc, initial_skc_len);
	data[initial_skc_len - 1] = '\0';
	size = strlen(data);

	copy = memblock_alloc(size, SMP_CACHE_BYTES);
	if (!copy) {
		pr_err("Failed to allocate memory for structured kernel cmdline\n");
		goto end;
	}
	strcpy(copy, data);

	skc_init(copy);
end:
	early_memunmap(data, initial_skc_len);
}
