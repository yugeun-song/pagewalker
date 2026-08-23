#ifndef PAGEWALKER_USER_REPORT_H
#define PAGEWALKER_USER_REPORT_H

#include <stddef.h>

#include "../include/pagewalker_common.h"

#define BUFFER_SIZE 16384

/* ------------------------------------------------------------------------- *
 * Architecture identity (user side)
 *
 * The report skeleton is shared; only the arch / root-register names and the
 * page-table entry flag decoding (in report.c) are hardware-defined. The walk
 * geometry (level count, VA width, page size) is reported by the kernel at
 * runtime, so the address breakdown and the step list are computed, not
 * hardcoded.
 * ------------------------------------------------------------------------- */
#if defined(__x86_64__)
#define PW_ARCH_NAME "x86-64"
#define PW_ROOT_REG_NAME "CR3"
#define PW_CONT_TERM "contiguous"
#elif defined(__aarch64__)
#define PW_ARCH_NAME "arm64"
#define PW_ROOT_REG_NAME "TTBR0_EL1"
#define PW_CONT_TERM "ARM64 contiguous (cont-PTE/cont-PMD)"
#elif defined(__riscv) && (__riscv_xlen == 64)
#define PW_ARCH_NAME "riscv64"
#define PW_ROOT_REG_NAME "satp"
#define PW_CONT_TERM "RISC-V NAPOT"
#else
#error "pagewalker: unsupported architecture (need x86-64, arm64, or riscv64)"
#endif

/* Render the full walk report into `buf` (BUFFER_SIZE bytes); returns length. */
int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid,
                 int kernel_mode);

/* Short name of the page-table level that held the final leaf entry. */
const char *leaf_level_name(unsigned int lvl);

/* Format a byte count as an exact binary-unit string (e.g. "2 MiB", "64 KiB"). */
void human_size(char *out, size_t cap, unsigned long long bytes);

#endif /* PAGEWALKER_USER_REPORT_H */
