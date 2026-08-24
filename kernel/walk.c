// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/pfn.h>
#include <linux/pgtable.h>
#include <linux/io.h>
#include <linux/bits.h>
#include <linux/threads.h>

#include "pagewalker.h"
#include "arch.h"

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

/* Record the arch-global walk geometry (level count, page size, VA width). */
void pw_set_geometry(struct pagewalker_result *res)
{
	res->paging_level = arch_paging_level();
	res->page_shift = PAGE_SHIFT;
	res->va_bits = arch_va_bits();
}

/*
 * Architecture-neutral core of the walk, rooted at an explicit pgd table rather
 * than at an mm. `pgd_root` is mm->pgd for a process walk and the kernel root
 * (arch_kernel_pgd()) for a kernel walk. `mm` is non-NULL only for a process
 * walk: it is used solely to take the PTE-level page-table lock that blocks a
 * khugepaged collapse. Kernel page tables (text / linear map / vmalloc) are not
 * collapsed under us, so the kernel walk passes mm == NULL and skips that lock.
 * Returns a short human reason for the log; res->is_valid distinguishes mapped
 * from not-mapped. The caller must set res->target_vaddr and the geometry, and
 * (for a process walk) hold mmap_read_lock(mm) across the call.
 */
const char *pw_walk_levels(struct mm_struct *mm, pgd_t *pgd_root,
			   struct pagewalker_result *res)
{
	unsigned long vaddr = res->target_vaddr;
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

	/*
	 * Root page-table base = the value programmed into the arch root
	 * translation register (CR3 / TTBR0_EL1|TTBR1_EL1 / satp.PPN<<PAGE_SHIFT).
	 */
	res->root_table_phys = virt_to_phys(pgd_root);

	res->pgd_idx = pgd_index(vaddr);
	pgd = pgd_root + pgd_index(vaddr);
	pgde = pgdp_get(pgd);
	res->pgd_base_phys = virt_to_phys(pgd_root);
	res->pgd_val = pgd_val(pgde);
	res->pgd_readback = read_entry_phys(res->pgd_base_phys + res->pgd_idx * ENTRY_SIZE);

	if (pgd_none(pgde) || pgd_bad(pgde))
		return "PGD entry empty or bad";

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

	if (p4d_none(p4de))
		return "P4D entry empty";

	if (p4d_leaf(p4de)) {
		/* See the pud_leaf() note: gate residency via pte_present() mirror. */
		if (!entry_present(p4d_val(p4de)))
			return "P4D huge entry not present (swap/migration)";
		set_leaf(res, vaddr, arch_entry_to_table_phys(p4d_val(p4de)),
			 p4d_leaf_size(p4de), PW_LEAF_P4D, false);
		read_physical_content(res);
		return "mapped via P4D-level huge page";
	}

	if (p4d_bad(p4de))
		return "P4D entry bad";

	res->pud_idx = pud_index(vaddr);
	pud = pw_pud_offset(p4d, vaddr);
	pude = pudp_get(pud);
	res->pud_base_phys = arch_entry_to_table_phys(p4d_val(p4de));
	res->pud_val = pud_val(pude);
	res->pud_readback = read_entry_phys(res->pud_base_phys + res->pud_idx * ENTRY_SIZE);

	if (pud_none(pude))
		return "PUD entry empty";

	if (pud_leaf(pude)) {
		/*
		 * pud_leaf() reports a 1G mapping but says nothing about residency.
		 * Gate on entry_present() (a pte_present() mirror) so a swapped or
		 * migrating huge entry is rejected while a resident PROT_NONE / NUMA-
		 * balancing huge page stays valid.
		 */
		if (!entry_present(pud_val(pude)))
			return "PUD huge entry not present (swap/migration)";
		set_leaf(res, vaddr, PFN_PHYS(pud_pfn(pude)),
			 pud_leaf_size(pude), PW_LEAF_PUD,
			 pud_leaf_size(pude) != PUD_SIZE);
		read_physical_content(res);
		return "mapped via PUD-level huge page";
	}

	if (pud_bad(pude))
		return "PUD entry bad";

	res->pmd_idx = pmd_index(vaddr);
	pmd = pmd_offset(pud, vaddr);
	pmde = pmdp_get_lockless(pmd);
	res->pmd_base_phys = arch_entry_to_table_phys(pud_val(pude));
	res->pmd_val = pmd_val(pmde);
	res->pmd_readback = read_entry_phys(res->pmd_base_phys + res->pmd_idx * ENTRY_SIZE);

	if (pmd_none(pmde))
		return "PMD entry empty";

	if (pmd_leaf(pmde)) {
		/* See the pud_leaf() note: present|protnone, mirroring pte_present(). */
		if (!entry_present(pmd_val(pmde)))
			return "PMD huge entry not present (swap/migration)";
		set_leaf(res, vaddr, PFN_PHYS(pmd_pfn(pmde)),
			 pmd_leaf_size(pmde), PW_LEAF_PMD,
			 pmd_leaf_size(pmde) != PMD_SIZE);
		read_physical_content(res);
		return "mapped via PMD-level huge page";
	}

	if (pmd_bad(pmde))
		return "PMD entry bad";

	res->pte_idx = pte_index(vaddr);
	res->pte_base_phys = arch_entry_to_table_phys(pmd_val(pmde));

	if (mm) {
		spinlock_t *ptl;

		/*
		 * The PTE table can be retracted under us by khugepaged /
		 * MADV_COLLAPSE, which clears the pmd and RCU-frees the PTE page.
		 * The exported, RCU-safe pte_offset_map_lock() is unavailable to
		 * modules, so we take the PMD's own page-table lock (pmd_lock, an
		 * inline). That is a different lock from pte_offset_map_lock's
		 * PTE-page ptl, but collapse clears the pmd via pmdp_collapse_flush()
		 * while holding exactly this lock, so holding it and re-validating
		 * the pmd blocks the clear that would detach the PTE page. We
		 * snapshot the entry, then drop the lock. 64-bit arches have no
		 * highmem, so pte_offset_kernel() needs no kmap.
		 */
		ptl = pmd_lock(mm, pmd);
		pmde = pmdp_get(pmd);
		if (pmd_none(pmde) || pmd_leaf(pmde) || pmd_bad(pmde)) {
			spin_unlock(ptl);
			return "PMD changed during walk (collapse race)";
		}
		pte = pte_offset_kernel(pmd, vaddr);
		pte_entry = ptep_get(pte);
		/* Read back the PTE slot while the lock still pins the table. */
		res->pte_readback = read_entry_phys(res->pte_base_phys + res->pte_idx * ENTRY_SIZE);
		spin_unlock(ptl);
	} else {
		/* Kernel walk: no collapse race, so read the leaf table directly. */
		pte = pte_offset_kernel(pmd, vaddr);
		pte_entry = ptep_get(pte);
		res->pte_readback = read_entry_phys(res->pte_base_phys + res->pte_idx * ENTRY_SIZE);
	}

	res->pte_val = pte_val(pte_entry);

	/*
	 * Only a present entry maps real RAM. A non-none, non-present PTE is a
	 * swap / migration entry whose bits are NOT a PFN; pte_present() also
	 * keeps genuine PROT_NONE / NUMA-balancing pages (resident) as valid.
	 */
	if (!pte_present(pte_entry))
		return "PTE not present (swapped out or unmapped)";

	/*
	 * pte_leaf_size() returns the base granule for an ordinary 4K PTE, but the
	 * full contiguous span for an arm64 cont-PTE (64K) or a riscv NAPOT leaf
	 * (64K). set_leaf() then rounds the base and widens the offset accordingly,
	 * so a contiguous mapping resolves the correct physical address even when
	 * the target offset lies above the base granule.
	 */
	{
		u64 sz = pte_leaf_size(pte_entry);

		set_leaf(res, vaddr, PFN_PHYS(pte_pfn(pte_entry)), sz,
			 PW_LEAF_PTE, sz != PAGE_SIZE);
		read_physical_content(res);
		return (sz != PAGE_SIZE) ? "mapped via PTE contiguous page"
					 : "mapped via PTE 4K page";
	}
}

int perform_page_walk(pid_t pid, struct pagewalker_result *res)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	unsigned long vaddr = res->target_vaddr;
	const char *reason;

	/* Validate the request before acquiring any process resources. */
	if (pid < 0 || pid >= PID_MAX_LIMIT) {
		pr_info_ratelimited("pid %d: rejected (pid out of range)\n", pid);
		return -EINVAL;
	}

	pw_set_geometry(res);

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
		return -ESRCH; /* kernel thread or exiting task: no mm */
	}

	mmap_read_lock(mm);
	reason = pw_walk_levels(mm, mm->pgd, res);

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

/*
 * Walk a KERNEL virtual address. There is no task mm: we root the walk at the
 * arch kernel table (CR3 on x86-64, TTBR1_EL1 on arm64, satp on riscv) and take
 * no mm lock. Kernel mappings for text / rodata / linear map / page tables are
 * stable, so this is safe; a bogus address folds to an empty entry and stops.
 */
int perform_kernel_walk(struct pagewalker_result *res)
{
	unsigned long vaddr = res->target_vaddr;
	pgd_t *root = arch_kernel_pgd();
	const char *reason;

	pw_set_geometry(res);
	if (!root) {
		res->is_valid = 0;
		pr_info_ratelimited("kernel vaddr 0x%lx: rejected (kernel walk unsupported on this arm64 PA config)\n",
				    vaddr);
		return RET_SUCCESS;
	}
	reason = pw_walk_levels(NULL, root, res);

	if (res->is_valid)
		pr_info_ratelimited("kernel vaddr 0x%lx -> phys 0x%llx [%s]\n",
				    vaddr, res->final_phys_addr, reason);
	else
		pr_info_ratelimited("kernel vaddr 0x%lx: walk stopped [%s]\n",
				    vaddr, reason);
	return RET_SUCCESS;
}
