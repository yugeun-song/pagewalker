// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/pfn.h>
#include <linux/pgtable.h>
#include <linux/io.h>
#include <linux/threads.h>

#include "../include/pagewalker_common.h"

#define MASK_CANONICAL_48      0xFFFF000000000000ULL
#define MASK_CANONICAL_57      0xFE00000000000000ULL
#define SHIFT_SIGN_BIT_48      47
#define SHIFT_SIGN_BIT_57      56
#define RET_SUCCESS            0
#define BIT_IS_SET             1


MODULE_DESCRIPTION("x86-64 Page Table Walker with Phys Verification");
MODULE_AUTHOR("Yugeun Song");
MODULE_LICENSE("GPL");

static long pagewalker_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations pagewalker_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pagewalker_ioctl,
};

static struct miscdevice pagewalker_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = PAGEWALKER_DEVICE_NAME,
	.fops = &pagewalker_fops,
};

static unsigned long get_phys_mask(void)
{
	return PHYSICAL_PAGE_MASK;
}

static int is_canonical_address(unsigned long vaddr, int paging_level)
{
	unsigned long sign_bit;
	unsigned long upper_bits;
	unsigned long mask;
	unsigned long shift;

	/*
	 * 5-level (LA57) support is gated at runtime via pgtable_l5_enabled(),
	 * not by a compile-time macro: the kernel decides 4- vs 5-level at boot,
	 * so the mask/shift must follow the detected paging_level.
	 */
	if (paging_level == PAGING_LEVEL_5) {
		shift = SHIFT_SIGN_BIT_57;
		mask = MASK_CANONICAL_57;
	} else {
		shift = SHIFT_SIGN_BIT_48;
		mask = MASK_CANONICAL_48;
	}

	sign_bit = (vaddr >> shift) & 1;
	upper_bits = vaddr & mask;

	if (sign_bit)
		return (upper_bits == mask);
	return (upper_bits == 0);
}

/*
 * Safe Physical Memory Reader
 * Validates memory presence and performs fault-tolerant reading.
 */
static void read_physical_content(struct pagewalker_result *res)
{
	void *kaddr;
	unsigned long val = 0;

	/*
	 * pfn_valid() only confirms a struct page / memmap entry exists for the
	 * frame. It does NOT prove the frame is usable RAM (it may be a reserved
	 * E820 region or a hole inside an otherwise-present section). The actual
	 * fault-safety comes from copy_from_kernel_nofault() below, which catches
	 * a bad access instead of panicking. We validate the EXACT pfn we read
	 * (final_phys_addr), which for a huge page differs from the page base.
	 */
	if (!pfn_valid(PHYS_PFN(res->final_phys_addr))) {
		res->value_at_phys = 0xffffffffffffffff;
		return;
	}

	/* Get Kernel Virtual Address (Direct Mapping) */
	kaddr = phys_to_virt(res->final_phys_addr);

	/*
	 * Fault-tolerant read: copy_from_kernel_nofault() probes the address
	 * and returns an error (leaving the sentinel) instead of faulting.
	 */
	res->value_at_phys = 0xffffffffffffffff;
	copy_from_kernel_nofault(&res->value_at_phys, kaddr, sizeof(val));
}

/*
 * Independent cross-check: read the 8-byte entry straight from its physical
 * slot (base + index * 8) via the direct map. This confirms the physical
 * address the tool reports really holds the value the walk obtained through
 * the page-table pointer. copy_from_kernel_nofault() keeps a bad / faulting
 * slot from panicking; the sentinel then shows up as a mismatch.
 */
static u64 read_entry_phys(unsigned long slot_phys)
{
	u64 val = ~0ULL;

	if (!pfn_valid(PHYS_PFN(slot_phys)))
		return val;

	copy_from_kernel_nofault(&val, phys_to_virt(slot_phys), sizeof(val));
	return val;
}

static int perform_page_walk(pid_t pid, struct pagewalker_result *res)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pgd_t pgde;
	p4d_t p4de;
	pud_t pude;
	pmd_t pmde;
	pte_t pte_entry;
	spinlock_t *ptl;
	unsigned long vaddr = res->target_vaddr;
	unsigned long phys_mask = get_phys_mask();
	const char *reason = "incomplete walk";

	/* Validate the request before acquiring any process resources. */
	if (pid < 0 || pid >= PID_MAX_LIMIT) {
		pr_info_ratelimited("pid %d: rejected (pid out of range)\n", pid);
		return -EINVAL;
	}

	res->paging_level = pgtable_l5_enabled() ? PAGING_LEVEL_5 : PAGING_LEVEL_4;
	if (!is_canonical_address(vaddr, res->paging_level)) {
		pr_info_ratelimited("pid %d vaddr 0x%lx: rejected (non-canonical address)\n",
				    pid, vaddr);
		return -EADDRNOTAVAIL;
	}

	pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		pr_info_ratelimited("pid %d: rejected (no such process)\n", pid);
		return -ESRCH;
	}

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task) {
		pr_info_ratelimited("pid %d: rejected (task exited)\n", pid);
		return -ESRCH;
	}

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) {
		pr_info_ratelimited("pid %d: rejected (no mm: kernel thread or exiting)\n", pid);
		return -ESRCH;		/* kernel thread or exiting task: no mm */
	}

	mmap_read_lock(mm);

	res->cr3_phys = virt_to_phys(mm->pgd);

	res->pgd_idx = pgd_index(vaddr);
	pgd = pgd_offset(mm, vaddr);
	pgde = pgdp_get(pgd);
	res->pgd_base_phys = virt_to_phys(mm->pgd);
	res->pgd_val = pgd_val(pgde);
	res->pgd_readback = read_entry_phys(res->pgd_base_phys + res->pgd_idx * 8);

	if (pgd_none(pgde) || pgd_bad(pgde)) {
		reason = "PGD entry empty or bad";
		goto out_unlock;
	}

	res->p4d_idx = p4d_index(vaddr);
	p4d = p4d_offset(pgd, vaddr);
	p4de = p4dp_get(p4d);
	if (res->paging_level == PAGING_LEVEL_5)
		res->p4d_base_phys = pgd_val(pgde) & phys_mask;
	else
		res->p4d_base_phys = res->pgd_base_phys;
	res->p4d_val = p4d_val(p4de);
	res->p4d_readback = read_entry_phys(res->p4d_base_phys + res->p4d_idx * 8);

	if (p4d_none(p4de) || p4d_bad(p4de)) {
		reason = "P4D entry empty or bad";
		goto out_unlock;
	}

	res->pud_idx = pud_index(vaddr);
	pud = pud_offset(p4d, vaddr);
	pude = pudp_get(pud);
	res->pud_base_phys = p4d_val(p4de) & phys_mask;
	res->pud_val = pud_val(pude);
	res->pud_readback = read_entry_phys(res->pud_base_phys + res->pud_idx * 8);

	if (pud_none(pude)) {
		reason = "PUD entry empty";
		goto out_unlock;
	}

	if (pud_leaf(pude)) {
		/*
		 * pud_leaf() only tests _PAGE_PSE. Mirror pte_present() and gate on
		 * _PAGE_PRESENT | _PAGE_PROTNONE: this rejects a mid-split, swapped
		 * or migrating huge entry (PSE set, both bits clear) while keeping a
		 * resident PROT_NONE / NUMA-balancing huge page valid. pud_present()
		 * is unusable here: it counts _PAGE_PSE itself as present.
		 */
		if (!(pud_val(pude) & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
			reason = "1G huge entry not present (swap/migration)";
			goto out_unlock;
		}
		reason = "mapped via 1G huge page";
		res->page_offset = vaddr & ~PUD_MASK;
		res->page_base_phys = PFN_PHYS(pud_pfn(pude));
		res->final_phys_addr = res->page_base_phys + res->page_offset;
		res->is_valid = BIT_IS_SET;
		read_physical_content(res);
		goto out_unlock;
	}

	if (pud_bad(pude)) {
		reason = "PUD entry bad";
		goto out_unlock;
	}

	res->pmd_idx = pmd_index(vaddr);
	pmd = pmd_offset(pud, vaddr);
	pmde = pmdp_get_lockless(pmd);
	res->pmd_base_phys = pud_val(pude) & phys_mask;
	res->pmd_val = pmd_val(pmde);
	res->pmd_readback = read_entry_phys(res->pmd_base_phys + res->pmd_idx * 8);

	if (pmd_none(pmde)) {
		reason = "PMD entry empty";
		goto out_unlock;
	}

	if (pmd_leaf(pmde)) {
		/* See the pud_leaf() note: present|protnone, mirroring pte_present(). */
		if (!(pmd_val(pmde) & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
			reason = "2M huge entry not present (swap/migration)";
			goto out_unlock;
		}
		reason = "mapped via 2M huge page";
		res->page_offset = vaddr & ~PMD_MASK;
		res->page_base_phys = PFN_PHYS(pmd_pfn(pmde));
		res->final_phys_addr = res->page_base_phys + res->page_offset;
		res->is_valid = BIT_IS_SET;
		read_physical_content(res);
		goto out_unlock;
	}

	if (pmd_bad(pmde)) {
		reason = "PMD entry bad";
		goto out_unlock;
	}

	res->pte_idx = pte_index(vaddr);
	res->pte_base_phys = pmd_val(pmde) & phys_mask;

	/*
	 * The PTE table can be retracted under us by khugepaged / MADV_COLLAPSE,
	 * which clears the pmd and RCU-frees the PTE page. The exported, RCU-safe
	 * pte_offset_map_lock() is unavailable to modules, so we take the PMD's
	 * own page-table lock (pmd_lock, an inline). That is a different lock from
	 * pte_offset_map_lock's PTE-page ptl, but collapse clears the pmd via
	 * pmdp_collapse_flush() while holding exactly this lock, so holding it and
	 * re-validating the pmd blocks the clear that would detach the PTE page.
	 * We snapshot the entry, then drop the lock. x86-64 has no highmem, so
	 * pte_offset_kernel() needs no kmap.
	 */
	ptl = pmd_lock(mm, pmd);
	pmde = pmdp_get(pmd);
	if (pmd_none(pmde) || pmd_leaf(pmde) || pmd_bad(pmde)) {
		reason = "PMD changed during walk (collapse race)";
		spin_unlock(ptl);
		goto out_unlock;
	}
	pte = pte_offset_kernel(pmd, vaddr);
	pte_entry = ptep_get(pte);
	/* Read back the PTE slot while still holding the lock that pins the table. */
	res->pte_readback = read_entry_phys(res->pte_base_phys + res->pte_idx * 8);
	spin_unlock(ptl);

	res->pte_val = pte_val(pte_entry);

	/*
	 * Only a present entry maps real RAM. A non-none, non-present PTE is a
	 * swap / migration entry whose bits are NOT a PFN; pte_present() also
	 * keeps genuine PROT_NONE / NUMA-balancing pages (resident) as valid.
	 */
	if (!pte_present(pte_entry)) {
		reason = "PTE not present (swapped out or unmapped)";
		goto out_unlock;
	}

	reason = "mapped via 4K page";
	res->page_offset = vaddr & ~PAGE_MASK;
	res->page_base_phys = PFN_PHYS(pte_pfn(pte_entry));
	res->final_phys_addr = res->page_base_phys | res->page_offset;
	res->is_valid = BIT_IS_SET;

	read_physical_content(res);

out_unlock:
	if (res->is_valid)
		pr_info_ratelimited("pid %d vaddr 0x%lx -> phys 0x%llx [%s]\n",
				    pid, vaddr, res->final_phys_addr, reason);
	else
		pr_info_ratelimited("pid %d vaddr 0x%lx: walk stopped [%s]\n",
				    pid, vaddr, reason);

	mmap_read_unlock(mm);
	mmput(mm);
	return RET_SUCCESS;
}

static long pagewalker_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pagewalker_request req;
	__u64 saved_vaddr;
	int ret;

	if (cmd != PAGEWALKER_IOC_GET_INFO)
		return -ENOTTY;
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	/* Preserve the caller-supplied input; zero the rest of the result. */
	saved_vaddr = req.info.target_vaddr;
	memset(&req.info, 0, sizeof(req.info));
	req.info.target_vaddr = saved_vaddr;

	/*
	 * A negative return is a hard error (bad pid / non-canonical address /
	 * no such task) reported via errno. A completed walk returns 0 with
	 * res->is_valid telling apart "mapped" from "not mapped".
	 */
	ret = perform_page_walk(req.pid, &req.info);
	if (ret < 0)
		return ret;

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return RET_SUCCESS;
}

static int __init pagewalker_init(void)
{
	int ret = misc_register(&pagewalker_device);

	if (ret) {
		pr_err("failed to register misc device: %d\n", ret);
		return ret;
	}

	pr_info("loaded: /dev/%s ready (minor %d)\n",
		PAGEWALKER_DEVICE_NAME, pagewalker_device.minor);
	return ret;
}

static void __exit pagewalker_exit(void)
{
	misc_deregister(&pagewalker_device);
	pr_info("unloaded\n");
}

module_init(pagewalker_init);
module_exit(pagewalker_exit);
