/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ATOMIC64_64_H
#define _ASM_X86_ATOMIC64_64_H

#include <linux/types.h>
#include <asm/alternative.h>
#include <asm/cmpxchg.h>

/* The 64-bit atomic type */

#define ATOMIC64_INIT(i)	{ (i) }

/**
 * arch_atomic64_read - read atomic64 variable
 * @v: pointer to atomic64_t
 *
 * Atomically reads and returns the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long arch_atomic64_read(const atomic64_t *v)
{
	return READ_ONCE(v->counter);
}

/**
 * arch_atomic64_set - set atomic64 variable
 * @v: pointer to atomic64_t
 * @i: new value
 *
 * Atomically sets the value of @v to @i.
 * Doesn't imply a write memory barrier.
 */
static inline void arch_atomic64_set(atomic64_t *v, long i)
{
	WRITE_ONCE(v->counter, i);
}

/**
 * arch_atomic64_[add|sub] - add|subtract integer to/from atomic64 variable
 * @i: integer value to add/subtract
 * @v: pointer to atomic64_t
 *
 * Atomically adds/subtracts @i to/from @v.
 */
static __always_inline void arch_atomic64_sub(long i, atomic64_t *v)
{
	asm(LOCK_PREFIX "subq %1,%0" : "=m" (v->counter) : "er" (i), "m" (v->counter));
}

static __always_inline void arch_atomic64_add(long i, atomic64_t *v)
{
	asm(LOCK_PREFIX "addq %1,%0" : "=m" (v->counter) : "er" (i), "m" (v->counter));
}

/**
 * arch_atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer to atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false otherwise.
 */
static inline bool arch_atomic64_sub_and_test(long i, atomic64_t *v)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "subq", v->counter, "er", i, "%0", e);
}

/**
 * arch_atomic64_[inc|dec] - increment/decrement atomic64 variable
 * @v: pointer to atomic64_t
 *
 * Atomically increments/decrements @v by 1.
 */
static __always_inline void arch_atomic64_inc(atomic64_t *v)
{
	asm(LOCK_PREFIX "incq %0" : "=m" (v->counter) : "m" (v->counter));
}

static __always_inline void arch_atomic64_dec(atomic64_t *v)
{
	asm(LOCK_PREFIX "decq %0" : "=m" (v->counter) : "m" (v->counter));
}

/**
 * arch_atomic64_[inc|dec]_and_test - increment/decrement and test
 * @v: pointer to atomic64_t
 *
 * Atomically increments/decrements @v by 1 and
 * returns true if the result is 0, or false otherwise.
 */
static inline bool arch_atomic64_dec_and_test(atomic64_t *v)
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "decq", v->counter, "%0", e);
}

static inline bool arch_atomic64_inc_and_test(atomic64_t *v)
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "incq", v->counter, "%0", e);
}

/**
 * arch_atomic64_add_negative - add and test if negative
 * @i: integer value to add
 * @v: pointer to atomic64_t
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false otherwise.
 */
static inline bool arch_atomic64_add_negative(long i, atomic64_t *v)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "addq", v->counter, "er", i, "%0", s);
}

/**
 * arch_atomic64_[add|sub]_return - add/subtract and return
 * @i: integer value to add/subtract
 * @v: pointer to atomic64_t
 *
 * Atomically adds/subtracts @i to/from @v and returns the new value of @v.
 */
static __always_inline long arch_atomic64_add_return(long i, atomic64_t *v)
{
	return xadd(&v->counter, +i) + i;
}

static __always_inline long arch_atomic64_sub_return(long i, atomic64_t *v)
{
	return xadd(&v->counter, -i) - i;
}

/**
 * arch_atomic64_fetch_[add|sub]_return - add/subtract and return old value
 * @i: integer value to add/subtract
 * @v: pointer to atomic64_t
 *
 * Atomically adds/subtracts @i to/from @v and returns the old value of @v.
 */
static __always_inline long arch_atomic64_fetch_add (long i, atomic64_t *v)
{
	return xadd(&v->counter, +i);
}

static __always_inline long arch_atomic64_fetch_sub (long i, atomic64_t *v)
{
	return xadd(&v->counter, -i);
}

/**
 * arch_atomic64_[inc|dec]_return - increment/decrement and return
 * @v: pointer to atomic64_t
 *
 * Atomically increments/decrements @v and returns the new value of @v.
 */
#define arch_atomic64_inc_return(v)  arch_atomic64_add_return(1, (v))
#define arch_atomic64_dec_return(v)  arch_atomic64_sub_return(1, (v))

static inline long arch_atomic64_cmpxchg(atomic64_t *v, long val_old, long val_new)
{
	return arch_cmpxchg(&v->counter, val_old, val_new);
}

#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg

static __always_inline bool arch_atomic64_try_cmpxchg(atomic64_t *v, s64 *val_old, long val_new)
{
	return try_cmpxchg(&v->counter, val_old, val_new);
}

static inline long arch_atomic64_xchg(atomic64_t *v, long val_new)
{
	return xchg(&v->counter, val_new);
}

/**
 * arch_atomic64_add_unless - add unless the number is a given value
 * @v: pointer to atomic64_t
 * @i: the amount to add to @v...
 * @u: ...unless @v is equal to @u
 *
 * Atomically adds @i to @v, so long as @v was not @u.
 * Returns true if the operation was performed, or false otherwise.
 */
static inline bool arch_atomic64_add_unless(atomic64_t *v, long i, long u)
{
	s64 val_old = arch_atomic64_read(v);

	do {
		if (unlikely(val_old == u))
			return false;
	} while (!arch_atomic64_try_cmpxchg(v, &val_old, val_old + i));

	return true;
}

#define arch_atomic64_inc_not_zero(v) arch_atomic64_add_unless((v), 1, 0)

/*
 * arch_atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer to type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * @v was not decremented.
 */
static inline long arch_atomic64_dec_if_positive(atomic64_t *v)
{
	s64 val_new, val_old = arch_atomic64_read(v);

	do {
		val_new = val_old - 1;
		if (unlikely(val_new < 0))
			break;
	} while (!arch_atomic64_try_cmpxchg(v, &val_old, val_new));

	return val_new;
}

static inline long arch_atomic64_fetch_and(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do { } while (!arch_atomic64_try_cmpxchg(v, &val, val & i));

	return val;
}

static inline long arch_atomic64_fetch_or(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do { } while (!arch_atomic64_try_cmpxchg(v, &val, val | i));

	return val;
}

static inline long arch_atomic64_fetch_xor(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do { } while (!arch_atomic64_try_cmpxchg(v, &val, val ^ i));

	return val;
}

static inline void arch_atomic64_or(long i, atomic64_t *v)
{
	asm(LOCK_PREFIX "orq  %1,%0" : "+m" (v->counter) : "er" (i) : "memory");
}

static inline void arch_atomic64_xor(long i, atomic64_t *v)
{
	asm(LOCK_PREFIX "xorq %1,%0" : "+m" (v->counter) : "er" (i) : "memory");
}

static inline void arch_atomic64_and(long i, atomic64_t *v)
{
	asm(LOCK_PREFIX "andq %1,%0" : "+m" (v->counter) : "er" (i) : "memory");
}

#endif /* _ASM_X86_ATOMIC64_64_H */
