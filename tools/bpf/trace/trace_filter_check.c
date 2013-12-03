/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <trace/bpf_trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

void *__kmalloc(size_t size, int flags)
{
	return calloc(size, 1);
}

void kfree(void *objp)
{
	free(objp);
}

int kmalloc_caches[128];
void *kmem_cache_alloc_trace(void *caches, int flags, size_t size)
{
	return calloc(size, 1);
}

void bpf_compile(void *prog)
{
}

void __bpf_free(void *prog)
{
}

int printk(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

char buf[16000];
int bpf_load_image(const char *image, int image_len, struct bpf_callbacks *cb,
		   void **p_prog);

int main(int ac, char **av)
{
	FILE *f;
	int size, err;
	void *prog;

	if (ac < 2) {
		printf("Usage: %s bpf_binary_image\n", av[0]);
		return 1;
	}

	f = fopen(av[1], "r");
	if (!f) {
		printf("fopen %s\n", strerror(errno));
		return 2;
	}
	size = fread(buf, 1, sizeof(buf), f);
	if (size <= 0) {
		printf("fread %s\n", strerror(errno));
		return 3;
	}
	err = bpf_load_image(buf, size, &bpf_trace_cb, &prog);
	if (!err)
		printf("OK\n");
	else
		printf("err %s\n", strerror(-err));
	fclose(f);
	return 0;
}
