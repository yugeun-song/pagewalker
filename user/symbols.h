#ifndef PAGEWALKER_USER_SYMBOLS_H
#define PAGEWALKER_USER_SYMBOLS_H

#include <stddef.h>

/*
 * Resolve a kernel address for -k. A 0x-prefixed argument is a raw address; any
 * other argument is a symbol name looked up in /proc/kallsyms. Returns 0 on
 * success, or: 1 = not found, 2 = resolved to 0 (kptr_restrict hides it),
 * 3 = /proc/kallsyms unreadable, 4 = malformed 0x address.
 */
int resolve_ksym(const char *arg, unsigned long long *out);

/*
 * Resolve a symbol name to a runtime address inside process `pid`, entirely in
 * userspace. Returns 0 on success, or fills errbuf and returns non-zero
 * (1 = not resolvable, 2 = /proc/pid/maps unreadable).
 */
int resolve_user_sym(unsigned int pid, const char *name,
                     unsigned long long *out, char *errbuf, size_t errcap);

#endif /* PAGEWALKER_USER_SYMBOLS_H */
