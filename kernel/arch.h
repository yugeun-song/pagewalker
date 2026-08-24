/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PAGEWALKER_KERNEL_ARCH_H
#define PAGEWALKER_KERNEL_ARCH_H

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/pfn.h>
#include <linux/bits.h>
#include <linux/io.h>

#include "../include/pagewalker_common.h"

/* ------------------------------------------------------------------------- *
 * Architecture layer
 *
 * The walk itself (pw_walk_levels) is architecture-neutral: it is driven by
 * the generic pgd/p4d/pud/pmd/pte accessors and the typed getters, which fold
 * the absent levels transparently on every arch. Only a few facts are hardware-
 * defined, so they are the only things isolated per arch here:
 *   - arch_paging_level()          how many levels are active (3 / 4 / 5)
 *   - arch_va_bits()               translated virtual-address width
 *   - arch_entry_to_table_phys()   entry value -> next table's physical base
 *   - arch_kernel_pgd()            root of the kernel half (hardware register)
 *   - arch_addr_representable()    which virtual addresses can be translated
 *   - pw_p4d_offset / pw_pud_offset  module-safe level descent
 * Everything else below the arch layer is shared source. These are static
 * inline so the header can be included by every translation unit that needs a
 * subset without tripping the unused-function warning.
 * ------------------------------------------------------------------------- */

#if defined(CONFIG_X86_64)

static inline int arch_paging_level(void)
{
	return pgtable_l5_enabled() ? PAGING_LEVEL_5 : PAGING_LEVEL_4;
}

static inline unsigned int arch_va_bits(void)
{
	return pgtable_l5_enabled() ? 57 : 48;
}

static inline u64 arch_entry_to_table_phys(u64 entry_val)
{
	/* The next-table physical base sits in place in the entry; mask it out. */
	return entry_val & PHYSICAL_PAGE_MASK;
}

/*
 * Root of the kernel half. init_mm / swapper are not exported to modules, so we
 * read the hardware root instead. On x86-64 the kernel PGD entries are cloned
 * into every process's page table, so CR3's current value already resolves a
 * kernel VA; read_cr3_pa() masks off PCID / the PTI bit to yield the pure base.
 */
static inline pgd_t *arch_kernel_pgd(void)
{
	return (pgd_t *)__va(read_cr3_pa());
}

/* x86 folds the upper levels inline, so the generic accessors are module-safe. */
#define pw_p4d_offset p4d_offset
#define pw_pud_offset pud_offset

#elif defined(CONFIG_ARM64)

static inline int arch_paging_level(void)
{
	/*
	 * With CONFIG_ARM64_LPA2 the top levels are enabled at runtime; otherwise
	 * the level count is fixed by CONFIG_PGTABLE_LEVELS. The runtime checks
	 * cover both: they fall through to the compile-time count when LPA2 is off.
	 */
	if (pgtable_l5_enabled())
		return PAGING_LEVEL_5;
	if (pgtable_l4_enabled())
		return PAGING_LEVEL_4;
	return CONFIG_PGTABLE_LEVELS;
}

static inline unsigned int arch_va_bits(void)
{
	/* vabits_actual reads TCR_EL1 at runtime for 52-bit configs, else VA_BITS. */
	return (unsigned int)vabits_actual;
}

static inline u64 arch_entry_to_table_phys(u64 entry_val)
{
	/* __pte_to_phys reassembles the relocated high PA bits under LPA2. */
	return __pte_to_phys(__pte(entry_val));
}

/*
 * Root of the kernel half. Unlike x86, the arm64 kernel table lives under
 * TTBR1_EL1 (swapper_pg_dir) and is NOT present in a task's TTBR0 pgd, so a
 * kernel VA cannot be resolved through mm->pgd. Read TTBR1_EL1 directly and
 * strip the ASID (bits [63:48]) and CnP (bit 0); the base is page-aligned for
 * the non-52-bit-PA configuration this module targets.
 */
static inline pgd_t *arch_kernel_pgd(void)
{
	u64 ttbr1 = read_sysreg(ttbr1_el1);

#if defined(CONFIG_ARM64_PA_BITS_52)
	/*
	 * Hard guard: on a 52-bit-PA kernel (FEAT_LPA / FEAT_LPA2) the pgd base's
	 * high physical-address bits [51:48] are encoded in TTBR1 outside the
	 * [47:12] field this mask keeps, so the extraction would silently drop them
	 * and yield a wrong root. Refuse the kernel walk (return NULL) rather than
	 * return wrong data; the caller maps NULL to an explicit -EOPNOTSUPP. This
	 * is compile-time, so an ordinary 48-bit-PA kernel is unaffected.
	 */
	(void)ttbr1;
	return NULL;
#else
	return (pgd_t *)__va(ttbr1 & GENMASK_ULL(47, PAGE_SHIFT));
#endif
}

/* arm64 folds the upper levels inline, so the generic accessors are module-safe. */
#define pw_p4d_offset p4d_offset
#define pw_pud_offset pud_offset

#elif defined(CONFIG_RISCV) && defined(CONFIG_64BIT)

/* RV64 stores a 44-bit PPN in PTE bits [53:10]; the flags live in bits [9:0]. */
#define PW_RISCV_PFN_MASK GENMASK_ULL(53, 10)

static inline int arch_paging_level(void)
{
	/* pgtable_l4_enabled / pgtable_l5_enabled are bare bool variables here. */
	if (pgtable_l5_enabled)
		return PAGING_LEVEL_5;
	if (pgtable_l4_enabled)
		return PAGING_LEVEL_4;
	return PAGING_LEVEL_3; /* Sv39 */
}

static inline unsigned int arch_va_bits(void)
{
	return (unsigned int)VA_BITS; /* Sv39/48/57 selected at runtime */
}

static inline u64 arch_entry_to_table_phys(u64 entry_val)
{
	return ((entry_val & PW_RISCV_PFN_MASK) >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
}

/*
 * Root of the kernel half. riscv has one root for the whole address space, and
 * the kernel mappings are cloned into every process's page table, so the value
 * programmed into satp already resolves a kernel VA. satp.PPN is the root PPN.
 */
static inline pgd_t *arch_kernel_pgd(void)
{
	return (pgd_t *)__va((csr_read(CSR_SATP) & SATP_PPN) << PAGE_SHIFT);
}

/*
 * riscv defines pud_offset()/p4d_offset() out-of-line in arch/riscv/mm and does
 * NOT export them, so a module cannot link against them (x86/arm64 fold these
 * inline). Replicate the kernel's exact runtime level-folding here using only
 * inline helpers and the exported pgtable_l4_enabled / pgtable_l5_enabled flags.
 */
static inline p4d_t *pw_p4d_offset(pgd_t *pgd, unsigned long addr)
{
	if (pgtable_l5_enabled)
		return pgd_pgtable(pgdp_get(pgd)) + p4d_index(addr);
	return (p4d_t *)pgd;
}

static inline pud_t *pw_pud_offset(p4d_t *p4d, unsigned long addr)
{
	if (pgtable_l4_enabled)
		return p4d_pgtable(p4dp_get(p4d)) + pud_index(addr);
	return (pud_t *)p4d;
}

#else
#error "pagewalker: unsupported architecture (need x86-64, arm64, or riscv64)"
#endif

/*
 * Is this virtual address translatable on this arch? x86-64 and riscv64 both
 * sign-extend (the bits above the sign bit must all equal it), only at a
 * different position (x86 47/56; riscv Sv39/48/57 -> bit 38/47/56). arm64 has
 * no two-sided canonical hole: a user address is strictly the low half, and a
 * top-byte tag (TBI) must be stripped before the range check.
 */
static inline bool arch_addr_representable(unsigned long vaddr, unsigned int va_bits)
{
#if defined(CONFIG_ARM64)
	return (untagged_addr(vaddr) >> va_bits) == 0;
#else
	unsigned long mask = ~((1UL << va_bits) - 1); /* bits [va_bits, 63] */
	unsigned long sign_bit = (vaddr >> (va_bits - 1)) & 1;
	unsigned long upper = vaddr & mask;

	return sign_bit ? (upper == mask) : (upper == 0);
#endif
}

#endif /* PAGEWALKER_KERNEL_ARCH_H */
