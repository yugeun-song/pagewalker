#ifndef PAGEWALKER_COMMON_H
#define PAGEWALKER_COMMON_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PAGEWALKER_DEVICE_NAME "pagewalker"
#define PAGEWALKER_PATH        "/dev/pagewalker"
#define PAGEWALKER_IOC_MAGIC   'k'
#define PAGEWALKER_CMD_ID      1
#define PAGEWALKER_CMD_READ    2
#define PAGING_LEVEL_3       3
#define PAGING_LEVEL_4       4
#define PAGING_LEVEL_5       5

/*
 * Which page-table level held the final leaf entry (result.mapping_level).
 * A leaf above PTE is a huge mapping; PW_LEAF_NONE means the walk did not
 * reach a present leaf.
 */
#define PW_LEAF_NONE         0
#define PW_LEAF_PTE          1
#define PW_LEAF_PMD          2
#define PW_LEAF_PUD          3
#define PW_LEAF_P4D          4

struct pagewalker_result {
	__u64 target_vaddr;

	int paging_level;

	/*
	 * Geometry the kernel detected at runtime, so the CLI can render the
	 * address-field breakdown for any arch/granule without hardcoding it:
	 * page_shift is log2(page size) (12/14/16), va_bits is the translated
	 * virtual-address width (x86 48/57, arm64 vabits_actual, riscv Sv39/48/57).
	 */
	__u32 page_shift;
	__u32 va_bits;

	/*
	 * Physical base of the root page table - the value programmed into the
	 * arch's root translation register: CR3 (x86-64), TTBR0_EL1 (arm64, the
	 * user half; TTBR1_EL1 holds the kernel half), or satp.PPN<<PAGE_SHIFT
	 * (riscv). Equal to virt_to_phys(mm->pgd) on every arch.
	 */
	__u64 root_table_phys;

	__u64 pgd_idx;
	__u64 p4d_idx;
	__u64 pud_idx;
	__u64 pmd_idx;
	__u64 pte_idx;
	__u64 page_offset;

	__u64 pgd_val;
	__u64 p4d_val;
	__u64 pud_val;
	__u64 pmd_val;
	__u64 pte_val;

	/*
	 * Independent read-back of each entry directly from its physical slot
	 * (base_phys + index*8, via phys_to_virt) - lets the tool prove that the
	 * physical address it reports really holds the entry value the walk got
	 * through the page-table pointer. 0 when that level was not walked.
	 */
	__u64 pgd_readback;
	__u64 p4d_readback;
	__u64 pud_readback;
	__u64 pmd_readback;
	__u64 pte_readback;

	__u64 pgd_base_phys;
	__u64 p4d_base_phys;
	__u64 pud_base_phys;
	__u64 pmd_base_phys;
	__u64 pte_base_phys;
	__u64 page_base_phys;
	__u64 final_phys_addr;

	/*
	 * Effective mapping geometry, filled when is_valid. page_size is the true
	 * size in bytes of the page backing target_vaddr - the actual leaf span,
	 * including arm64 contiguous (cont-PTE 64K / cont-PMD 32M) and riscv NAPOT
	 * runs, not just the base granule. mapping_level says which level held the
	 * leaf (PW_LEAF_PTE/PMD/PUD/P4D); is_contiguous is 1 for an arm64
	 * contiguous or riscv NAPOT leaf (page_size then exceeds the level's base
	 * size). page_base_phys/page_offset are relative to page_size.
	 */
	__u64 page_size;
	__u32 mapping_level;
	__u32 is_contiguous;

	/* Verification - Actual 8 bytes read from the physical address */
	__u64 value_at_phys;

	/* 1: Walk Success, 0: Fail */
	int is_valid;
};

struct pagewalker_request {
	__u32 pid;
	__u32 padding;
	struct pagewalker_result info;
};

#define PAGEWALKER_IOC_GET_INFO _IOWR(PAGEWALKER_IOC_MAGIC, PAGEWALKER_CMD_ID, struct pagewalker_request)

/* ------------------------------------------------------------------------- *
 * Bulk read (command 2)
 *
 * Command 1 above resolves ONE address and reports a single u64 at it. Command
 * 2 copies an arbitrary run of bytes out of a target address space into a
 * user-supplied buffer, and also returns the full walk of the START address so
 * the CLI can still print the translation. The walk is repeated per page inside
 * the run (physical frames are contiguous only to the end of a leaf), and every
 * copy is fault-tolerant, so a hole or an unmapped page truncates the result
 * instead of faulting. The request rides a distinct ioctl number so command 1's
 * ABI (its _IOWR size, hence its number) stays frozen.
 * ------------------------------------------------------------------------- */

/* flags */
#define PW_READ_F_KERNEL     (1u << 0)  /* vaddr is a kernel-space address; pid ignored */
#define PW_READ_F_ALLOW_MMIO (1u << 1)  /* permit reads of non-System-RAM (MMIO / reserved) */

/* stopped reason (out) */
#define PW_STOP_OK           0  /* the whole run was copied */
#define PW_STOP_UNMAPPED     1  /* a page in the run is not mapped / not present */
#define PW_STOP_FAULT        2  /* a physical/kernel read faulted (hole, bad frame) */
#define PW_STOP_NONCANON     3  /* the start address is not representable on this arch */
#define PW_STOP_TOOBIG       4  /* size exceeded the per-call maximum (clamped) */
#define PW_STOP_MMIO         5  /* a page is not System RAM; refused (pass allow-mmio) */

/* Upper bound on one call's size; the CLI loops for larger dumps. */
#define PW_READ_MAX          (16u << 20)  /* 16 MiB */

struct pagewalker_read_request {
	__u32 pid;              /* target pid (ignored when PW_READ_F_KERNEL) */
	__u32 flags;            /* PW_READ_F_* */
	__u64 vaddr;            /* first virtual address to read */
	__u64 size;             /* bytes requested */
	__u64 ubuf;             /* userspace destination buffer (pointer as integer) */

	__u64 bytes_read;       /* out: bytes actually copied into ubuf */
	__u32 stopped;          /* out: PW_STOP_* (0 = full run copied) */
	__u32 pad;

	struct pagewalker_result info;  /* out: full walk of the START vaddr */
};

#define PAGEWALKER_IOC_READ _IOWR(PAGEWALKER_IOC_MAGIC, PAGEWALKER_CMD_READ, struct pagewalker_read_request)

#endif
