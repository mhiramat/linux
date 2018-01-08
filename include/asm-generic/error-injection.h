/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_ERROR_INJECTION_H
#define _ASM_GENERIC_ERROR_INJECTION_H

#if defined(__KERNEL__) && !defined(__ASSEMBLY__)
enum {
	ERROR_RET_NONE,		/* Dummy value for undefined case */
	ERROR_RET_NULL,		/* Return NULL if failure */
	ERROR_RET_ERRNO,	/* Return -ERRNO if failure */
	ERROR_RET_ERR_NULL,	/* Return -ERRNO or NULL if failure */
};

struct error_injection_entry {
	unsigned long	addr;
	int		etype;
};

#ifdef CONFIG_FUNCTION_ERROR_INJECTION
/*
 * Whitelist ganerating macro. Specify functions which can be
 * error-injectable using this macro.
 */
#define ALLOW_ERROR_INJECTION(fname, _etype)				\
static struct error_injection_entry __used				\
	__attribute__((__section__("_error_injection_whitelist")))	\
	_eil_addr_##fname = {						\
		.addr = (unsigned long)fname,				\
		.etype = _etype,					\
	};
#else
#define ALLOW_ERROR_INJECTION(fname, _etype)
#endif
#endif

#endif /* _ASM_GENERIC_ERROR_INJECTION_H */
