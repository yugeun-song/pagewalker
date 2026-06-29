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
#include <linux/bits.h>
#include <linux/threads.h>

#include "../include/pagewalker_common.h"

#define RET_SUCCESS            0
#define BIT_IS_SET             1
#define ENTRY_SIZE             8	/* page-table entry is 8 bytes on every 64-bit arch */


MODULE_DESCRIPTION("Page Table Walker with Phys Verification (x86-64/arm64/riscv64)");
MODULE_AUTHOR("Yugeun Song");
MODULE_LICENSE("GPL");

/* ------------------------------------------------------------------------- *
 * Architecture layer
 *
 * The walk itself (perform_page_walk) is architecture-neutral: it is driven by
 * the generic pgd/p4d/pud/pmd/pte accessors and the typed getters, which fold
 * the absent levels transparently on every arch. Only four facts are hardware-
 * defined, so they are the only things isolated per arch here:
 *   - arch_paging_level()          how many levels are active (3 / 4 / 5)
 *   - arch_va_bits()               translated virtual-address width
 *   - arch_entry_to_table_phys()   entry value -> next table's physical base
 *   - arch_addr_representable()    which virtual addresses can be translated
 * Everything else below the arch layer is shared source.
 * ------------------------------------------------------------------------- */

#if defined(CONFIG_X86_64)

static int arch_paging_level(void)
{
	return pgtable_l5_enabled() ? PAGING_LEVEL_5 : PAGING_LEVEL_4;
}

static unsigned int arch_va_bits(void)
{
	return pgtable_l5_enabled() ? 57 : 48;
}

static u64 arch_entry_to_table_phys(u64 entry_val)
{
	/* The next-table physical base sits in place in the entry; mask it out. */
	return entry_val & PHYSICAL_PAGE_MASK;
}

/* x86 folds the upper levels inline, so the generic accessors are module-safe. */
#define pw_p4d_offset p4d_offset
#define pw_pud_offset pud_offset

#elif defined(CONFIG_ARM64)

static int arch_paging_level(void)
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

static unsigned int arch_va_bits(void)
{
	/* vabits_actual reads TCR_EL1 at runtime for 52-bit configs, else VA_BITS. */
	return (unsigned int)vabits_actual;
}

static u64 arch_entry_to_table_phys(u64 entry_val)
{
	/* __pte_to_phys reassembles the relocated high PA bits under LPA2. */
	return __pte_to_phys(__pte(entry_val));
}

/* arm64 folds the upper levels inline, so the generic accessors are module-safe. */
#define pw_p4d_offset p4d_offset
#define pw_pud_offset pud_offset

#elif defined(CONFIG_RISCV) && defined(CONFIG_64BIT)

/* RV64 stores a 44-bit PPN in PTE bits [53:10]; the flags live in bits [9:0]. */
#define PW_RISCV_PFN_MASK GENMASK_ULL(53, 10)

static int arch_paging_level(void)
{
	/* pgtable_l4_enabled / pgtable_l5_enabled are bare bool variables here. */
	if (pgtable_l5_enabled)
		return PAGING_LEVEL_5;
	if (pgtable_l4_enabled)
		return PAGING_LEVEL_4;
	return PAGING_LEVEL_3;		/* Sv39 */
}

static unsigned int arch_va_bits(void)
{
	return (unsigned int)VA_BITS;	/* Sv39/48/57 selected at runtime */
}

static u64 arch_entry_to_table_phys(u64 entry_val)
{
	return ((entry_val & PW_RISCV_PFN_MASK) >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
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
static bool arch_addr_representable(unsigned long vaddr, unsigned int va_bits)
{
#if defined(CONFIG_ARM64)
	return (untagged_addr(vaddr) >> va_bits) == 0;
#else
	unsigned long mask = ~((1UL << va_bits) - 1);	/* bits [va_bits, 63] */
	unsigned long sign_bit = (vaddr >> (va_bits - 1)) & 1;
	unsigned long upper = vaddr & mask;

	return sign_bit ? (upper == mask) : (upper == 0);
#endif
}

/*
 * Is a leaf entry actually resident? Mirrors pte_present(): a present or
 * PROT_NONE/NUMA entry maps real RAM, while a swap/migration entry does not.
 * This is portable - pte_present() on a reconstructed entry classifies a huge
 * leaf correctly on every arch (the present/valid bit is bit 0 everywhere, and
 * each arch keeps the relevant bits clear in its swap-entry encoding). It is
 * used instead of pmd_present()/pud_present() only so one expression serves all
 * three arches uniformly.
 */
static bool entry_present(u64 entry_val)
{
	return pte_present(__pte(entry_val));
}

/*
 * Record a resolved leaf uniformly for every level. size is the TRUE mapped
 * span from the arch's *_leaf_size() accessor, so it already folds in arm64
 * contiguous (cont-PTE/cont-PMD) and riscv NAPOT runs. We round the raw leaf
 * base down to that span and take the offset modulo it: this both reports the
 * huge page's real base and fixes the offset for contiguous/NAPOT leaves whose
 * span exceeds the base granule (a plain ~PAGE_MASK would drop the high offset
 * bits, e.g. va[15:12] of a riscv 64K NAPOT page). base_phys_raw is the leaf
 * entry's frame base (PFN_PHYS(*_pfn) or the arch table-phys extractor).
 */
static void set_leaf(struct pagewalker_result *res, unsigned long vaddr,
		     u64 base_phys_raw, u64 size, u32 level, bool contiguous)
{
	u64 mask = size - 1;

	res->page_size = size;
	res->mapping_level = level;
	res->is_contiguous = contiguous ? 1 : 0;
	res->page_base_phys = base_phys_raw & ~mask;
	res->page_offset = vaddr & mask;
	res->final_phys_addr = res->page_base_phys + res->page_offset;
	res->is_valid = BIT_IS_SET;
}

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
	 * region or a hole inside an otherwise-present section). The actual
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
 * slot from panicking; the sentinel then shows up as a mismatch. Page-table
 * pages are in the linear map on every 64-bit arch (no highmem), so
 * phys_to_virt() is valid here.
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
	const char *reason = "incomplete walk";

	/* Validate the request before acquiring any process resources. */
	if (pid < 0 || pid >= PID_MAX_LIMIT) {
		pr_info_ratelimited("pid %d: rejected (pid out of range)\n", pid);
		return -EINVAL;
	}

	res->paging_level = arch_paging_level();
	res->page_shift = PAGE_SHIFT;
	res->va_bits = arch_va_bits();

	if (!arch_addr_representable(vaddr, res->va_bits)) {
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

	/*
	 * Root page-table base = the value programmed into the arch root
	 * translation register (CR3 / TTBR0_EL1 / satp.PPN<<PAGE_SHIFT).
	 */
	res->root_table_phys = virt_to_phys(mm->pgd);

	res->pgd_idx = pgd_index(vaddr);
	pgd = pgd_offset(mm, vaddr);
	pgde = pgdp_get(pgd);
	res->pgd_base_phys = virt_to_phys(mm->pgd);
	res->pgd_val = pgd_val(pgde);
	res->pgd_readback = read_entry_phys(res->pgd_base_phys + res->pgd_idx * ENTRY_SIZE);

	if (pgd_none(pgde) || pgd_bad(pgde)) {
		reason = "PGD entry empty or bad";
		goto out_unlock;
	}

	res->p4d_idx = p4d_index(vaddr);
	p4d = pw_p4d_offset(pgd, vaddr);
	p4de = p4dp_get(p4d);
	/*
	 * For a hardware-present level the next table base comes from the entry;
	 * for a folded level the accessor returns the parent slot, so reuse the
	 * parent's base (its index, here 0, is added separately at read-back).
	 */
	if (res->paging_level == PAGING_LEVEL_5)
		res->p4d_base_phys = arch_entry_to_table_phys(pgd_val(pgde));
	else
		res->p4d_base_phys = res->pgd_base_phys;
	res->p4d_val = p4d_val(p4de);
	res->p4d_readback = read_entry_phys(res->p4d_base_phys + res->p4d_idx * ENTRY_SIZE);

	if (p4d_none(p4de)) {
		reason = "P4D entry empty";
		goto out_unlock;
	}

	if (p4d_leaf(p4de)) {
		/* See the pud_leaf() note: gate residency via pte_present() mirror. */
		if (!entry_present(p4d_val(p4de))) {
			reason = "P4D huge entry not present (swap/migration)";
			goto out_unlock;
		}
		reason = "mapped via P4D-level huge page";
		set_leaf(res, vaddr, arch_entry_to_table_phys(p4d_val(p4de)),
			 p4d_leaf_size(p4de), PW_LEAF_P4D, false);
		read_physical_content(res);
		goto out_unlock;
	}

	if (p4d_bad(p4de)) {
		reason = "P4D entry bad";
		goto out_unlock;
	}

	res->pud_idx = pud_index(vaddr);
	pud = pw_pud_offset(p4d, vaddr);
	pude = pudp_get(pud);
	res->pud_base_phys = arch_entry_to_table_phys(p4d_val(p4de));
	res->pud_val = pud_val(pude);
	res->pud_readback = read_entry_phys(res->pud_base_phys + res->pud_idx * ENTRY_SIZE);

	if (pud_none(pude)) {
		reason = "PUD entry empty";
		goto out_unlock;
	}

	if (pud_leaf(pude)) {
		/*
		 * pud_leaf() reports a 1G mapping but says nothing about residency.
		 * Gate on entry_present() (a pte_present() mirror) so a swapped or
		 * migrating huge entry is rejected while a resident PROT_NONE / NUMA-
		 * balancing huge page stays valid.
		 */
		if (!entry_present(pud_val(pude))) {
			reason = "PUD huge entry not present (swap/migration)";
			goto out_unlock;
		}
		reason = "mapped via PUD-level huge page";
		set_leaf(res, vaddr, PFN_PHYS(pud_pfn(pude)),
			 pud_leaf_size(pude), PW_LEAF_PUD,
			 pud_leaf_size(pude) != PUD_SIZE);
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
	res->pmd_base_phys = arch_entry_to_table_phys(pud_val(pude));
	res->pmd_val = pmd_val(pmde);
	res->pmd_readback = read_entry_phys(res->pmd_base_phys + res->pmd_idx * ENTRY_SIZE);

	if (pmd_none(pmde)) {
		reason = "PMD entry empty";
		goto out_unlock;
	}

	if (pmd_leaf(pmde)) {
		/* See the pud_leaf() note: present|protnone, mirroring pte_present(). */
		if (!entry_present(pmd_val(pmde))) {
			reason = "PMD huge entry not present (swap/migration)";
			goto out_unlock;
		}
		reason = "mapped via PMD-level huge page";
		set_leaf(res, vaddr, PFN_PHYS(pmd_pfn(pmde)),
			 pmd_leaf_size(pmde), PW_LEAF_PMD,
			 pmd_leaf_size(pmde) != PMD_SIZE);
		read_physical_content(res);
		goto out_unlock;
	}

	if (pmd_bad(pmde)) {
		reason = "PMD entry bad";
		goto out_unlock;
	}

	res->pte_idx = pte_index(vaddr);
	res->pte_base_phys = arch_entry_to_table_phys(pmd_val(pmde));

	/*
	 * The PTE table can be retracted under us by khugepaged / MADV_COLLAPSE,
	 * which clears the pmd and RCU-frees the PTE page. The exported, RCU-safe
	 * pte_offset_map_lock() is unavailable to modules, so we take the PMD's
	 * own page-table lock (pmd_lock, an inline). That is a different lock from
	 * pte_offset_map_lock's PTE-page ptl, but collapse clears the pmd via
	 * pmdp_collapse_flush() while holding exactly this lock, so holding it and
	 * re-validating the pmd blocks the clear that would detach the PTE page.
	 * We snapshot the entry, then drop the lock. 64-bit arches have no highmem,
	 * so pte_offset_kernel() needs no kmap.
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
	res->pte_readback = read_entry_phys(res->pte_base_phys + res->pte_idx * ENTRY_SIZE);
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

	/*
	 * pte_leaf_size() returns the base granule for an ordinary 4K PTE, but the
	 * full contiguous span for an arm64 cont-PTE (64K) or a riscv NAPOT leaf
	 * (64K). set_leaf() then rounds the base and widens the offset accordingly,
	 * so a contiguous mapping resolves the correct physical address even when
	 * the target offset lies above the base granule.
	 */
	{
		u64 sz = pte_leaf_size(pte_entry);

		reason = (sz != PAGE_SIZE) ? "mapped via PTE contiguous page"
					   : "mapped via PTE 4K page";
		set_leaf(res, vaddr, PFN_PHYS(pte_pfn(pte_entry)), sz,
			 PW_LEAF_PTE, sz != PAGE_SIZE);
	}

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
