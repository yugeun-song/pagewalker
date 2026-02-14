#ifndef PAGEWALK_COMMON_H
#define PAGEWALK_COMMON_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PAGEWALK_DEVICE_NAME "pagewalk"
#define PAGEWALK_PATH        "/dev/pagewalk"
#define PAGEWALK_IOC_MAGIC   'k'
#define PAGEWALK_CMD_ID      1
#define PAGING_LEVEL_4       4
#define PAGING_LEVEL_5       5

struct pagewalk_result {
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

struct pagewalk_request {
	__u32 pid;
	__u32 padding;
	struct pagewalk_result info;
};

#define PAGEWALK_IOC_GET_INFO _IOWR(PAGEWALK_IOC_MAGIC, PAGEWALK_CMD_ID, struct pagewalk_request)

#endif
