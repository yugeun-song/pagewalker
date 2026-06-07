#ifndef PAGEWALKER_COMMON_H
#define PAGEWALKER_COMMON_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PAGEWALKER_DEVICE_NAME "pagewalker"
#define PAGEWALKER_PATH        "/dev/pagewalker"
#define PAGEWALKER_IOC_MAGIC   'k'
#define PAGEWALKER_CMD_ID      1
#define PAGING_LEVEL_4       4
#define PAGING_LEVEL_5       5

struct pagewalker_result {
	__u64 target_vaddr;

	int paging_level;
	__u64 cr3_phys;

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

#endif
