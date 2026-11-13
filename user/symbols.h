#ifndef USER_SYMBOLS_H
#define USER_SYMBOLS_H

#include <stddef.h>

/*
 * Resolve a kernel address for -k. A 0x-prefixed argument is a raw address; any
 * other argument is a symbol name looked up in /proc/kallsyms. Returns 0 on
 * success, or: 1 = not found, 2 = resolved to 0 (kptr_restrict hides it),
 * 3 = /proc/kallsyms unreadable, 4 = malformed 0x address.
 */
int resolve_ksym(unsigned long long *const mut_out, const char *const arg);

/*
 * Resolve a symbol name to a runtime address inside process `pid`, entirely in
 * userspace. Returns 0 on success, or fills mut_errbuf and returns non-zero
 * (1 = not resolvable, 2 = /proc/pid/maps unreadable).
 */
int resolve_user_sym(unsigned long long *const mut_out, char *const mut_errbuf, size_t errcap,
                     unsigned int pid, const char *const name);

#endif /* USER_SYMBOLS_H */
