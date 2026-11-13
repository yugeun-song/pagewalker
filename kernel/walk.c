/* SPDX-License-Identifier: 0BSD */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "walk.h"

#include <linux/bits.h>
#include <linux/hugetlb_inline.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/pgtable.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/threads.h>
#include <linux/uaccess.h>

#include "arch.h"

#define ENTRY_SIZE 8 /* page-table entry is 8 bytes on every 64-bit arch */

/*
 * Is a leaf entry actually resident? Mirrors pte_present(): a present or
 * PROT_NONE/NUMA entry maps real RAM, while a swap/migration entry does not.
 * This is portable - pte_present() on a reconstructed entry classifies a huge
 * leaf correctly on every arch (the present/valid bit is bit 0 everywhere, and
 * each arch keeps the relevant bits clear in its swap-entry encoding). It is
 * used instead of pmd_present()/pud_present() only so one expression serves all
 * three arches uniformly.
 */
static bool is_entry_present(u64 entry_val)
{
	return pte_present(__pte(entry_val)) != 0;
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
static void set_leaf(struct pagewalker_result *const mut_res, unsigned long vaddr,
		     u64 base_phys_raw, u64 size, u32 level, bool is_contiguous)
{
	u64 mask = size - 1;

	mut_res->page_size = size;
	mut_res->mapping_level = level;
	mut_res->is_contiguous = (is_contiguous) ? 1 : 0;
	mut_res->page_base_phys = base_phys_raw & ~mask;
	mut_res->page_offset = vaddr & mask;
	mut_res->final_phys_addr = mut_res->page_base_phys + mut_res->page_offset;
	mut_res->is_valid = 1;
}

static struct folio *pw_pin_frame(u64 phys)
{
	struct page *page = pfn_to_online_page(PHYS_PFN(phys));
	if (page == NULL) {
		return NULL;
	}

	for (;;) {
		struct folio *folio = page_folio(page);

		if (!folio_try_get(folio)) {
			return NULL;
		}
		if (page_folio(page) == folio) {
			return folio;
		}
		folio_put(folio);
		folio = NULL;
	}
}

static void pw_unpin(struct folio **const mut_pin)
{
	if (*mut_pin != NULL) {
		folio_put(*mut_pin);
		*mut_pin = NULL;
	}
}

static bool pw_is_range_pinned(const struct folio *const pin_nullable, u64 phys, size_t len)
{
	if (pin_nullable == NULL) {
		return false;
	}

	u64 base = PFN_PHYS(folio_pfn(pin_nullable));

	return phys >= base && phys - base + len <= folio_size(pin_nullable);
}

/*
 * Safe Physical Memory Reader
 * Validates memory presence and performs fault-tolerant reading.
 */
static void read_physical_content(struct pagewalker_result *const mut_res,
				  const struct folio *const pin_nullable, bool needs_pin)
{
	/*
	 * pin_nullable is the folio reference the walk took on this frame while
	 * its mapping was still validated, so the frame cannot be freed and reused
	 * under the read; the u64 must lie inside that folio. A process walk
	 * (needs_pin) reads nothing it could not pin; a kernel walk may read an
	 * unpinnable frame (free page, refcount zero) since the kernel address
	 * space names the frame itself. A memmap entry does NOT prove the frame
	 * is usable RAM (it may be a reserved region or a hole inside an
	 * otherwise-present section). The actual fault-safety comes from
	 * copy_from_kernel_nofault() below, which catches a bad access instead of
	 * panicking. We validate the EXACT pfn we read (final_phys_addr), which for
	 * a huge page differs from the page base, and additionally gate on
	 * page_is_ram() so this single-u64 verification read is never turned into
	 * an MMIO/device-register access (the same hazard the bulk read refuses by
	 * default).
	 */
	bool can_read;

	if (pin_nullable != NULL) {
		can_read = pw_is_range_pinned(pin_nullable, mut_res->final_phys_addr,
					      sizeof(mut_res->value_at_phys));
	} else {
		can_read = !needs_pin && pfn_valid(PHYS_PFN(mut_res->final_phys_addr)) != 0;
	}
	if (!can_read || page_is_ram(PHYS_PFN(mut_res->final_phys_addr)) == 0) {
		mut_res->value_at_phys = 0xFFFFFFFFFFFFFFFF;
		return;
	}

	void *kaddr = phys_to_virt(mut_res->final_phys_addr);

	/*
	 * Fault-tolerant read: copy_from_kernel_nofault() probes the address
	 * and returns an error (leaving the sentinel) instead of faulting.
	 */
	mut_res->value_at_phys = 0xFFFFFFFFFFFFFFFF;
	copy_from_kernel_nofault(&mut_res->value_at_phys, kaddr, sizeof(mut_res->value_at_phys));
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

	if (pfn_valid(PHYS_PFN(slot_phys)) == 0) {
		return val;
	}

	copy_from_kernel_nofault(&val, phys_to_virt(slot_phys), sizeof(val));
	return val;
}

/* Record the arch-global walk geometry (level count, page size, VA width). */
static void pw_set_geometry(struct pagewalker_result *const mut_res)
{
	mut_res->paging_level = pw_arch_get_paging_level();
	mut_res->page_shift = PAGE_SHIFT;
	mut_res->va_bits = pw_arch_get_va_bits();
}

/*
 * Architecture-neutral core of the walk, rooted at an explicit pgd table rather
 * than at an mm. `pgd_root` is mm->pgd for a process walk and the kernel root
 * (pw_arch_get_kernel_pgd()) for a kernel walk. `mut_mm_nullable` is non-NULL only
 * for a process walk: it is used to take the page-table locks under which the
 * leaf is validated and its frame pinned (the PTE-level lock also blocks a
 * khugepaged collapse). Kernel page tables (text / linear map / vmalloc) are not
 * collapsed under us, so the kernel walk passes NULL and skips the locks.
 * Returns a short human reason for the log; mut_res->is_valid distinguishes
 * mapped from not-mapped. *mut_pin receives a folio reference on the mapped
 * frame (NULL if none could be taken); the caller drops it with pw_unpin() after
 * its read. The caller must set mut_res->target_vaddr and the geometry, and (for
 * a process walk) hold mmap_read_lock(mm) across the call.
 */
static const char *pw_walk_levels(struct pagewalker_result *const mut_res,
				  struct folio **const mut_pin,
				  struct mm_struct *const mut_mm_nullable, pgd_t *const pgd_root)
{
	unsigned long vaddr = pw_arch_untag_addr(mut_res->target_vaddr);
	bool is_hugetlb = false;

	*mut_pin = NULL;

	/*
	 * Anchor a process walk to a live VMA. munmap()/mremap()/brk-shrink detach
	 * VMAs under mmap_write_lock, then mmap_write_downgrade() and run
	 * free_pgtables() under the read lock - concurrently with a reader that also
	 * holds mmap_read_lock. Holding the read lock therefore does NOT exclude the
	 * teardown. But the detach happens under the write lock, so either we hold
	 * the read lock first (the writer blocks until we finish) or the VMA is
	 * already gone from the tree when we look it up here; confirming a VMA still
	 * covers vaddr keeps the walk off page tables being freed. free_pgtables'
	 * floor/ceiling never cross a live neighbouring VMA, so a covered address's
	 * tables stay put. A kernel walk (no mm) has no VMAs and is rooted at stable
	 * tables, so it skips this.
	 */
	if (mut_mm_nullable != NULL) {
		struct vm_area_struct *vma = find_vma(mut_mm_nullable, vaddr);

		if (vma == NULL || vaddr < vma->vm_start) {
			return "no VMA covers this address";
		}
		is_hugetlb = is_vm_hugetlb_page(vma);
	}

	/*
	 * Root page-table base = the value programmed into the arch root
	 * translation register (CR3 / TTBR0_EL1|TTBR1_EL1 / satp.PPN<<PAGE_SHIFT).
	 */
	mut_res->root_table_phys = virt_to_phys(pgd_root);

	mut_res->pgd_idx = pgd_index(vaddr);

	pgd_t *pgd = pgd_root + pgd_index(vaddr);
	pgd_t pgde = pgdp_get(pgd);

	mut_res->pgd_base_phys = virt_to_phys(pgd_root);
	mut_res->pgd_val = pgd_val(pgde);
	mut_res->pgd_readback = read_entry_phys(mut_res->pgd_base_phys +
						(mut_res->pgd_idx * ENTRY_SIZE));

	if (pgd_none(pgde) != 0 || pgd_bad(pgde) != 0) {
		return "PGD entry empty or bad";
	}

	mut_res->p4d_idx = p4d_index(vaddr);

	p4d_t *p4d = pw_get_p4d_slot(pgd, vaddr);
	p4d_t p4de = p4dp_get(p4d);

	/*
	 * For a hardware-present level the next table base comes from the entry;
	 * for a folded level the accessor returns the parent slot, so reuse the
	 * parent's base (its index, here 0, is added separately at read-back).
	 */
	if (mut_res->paging_level == PAGING_LEVEL_5) {
		mut_res->p4d_base_phys = pw_arch_extract_table_phys(pgd_val(pgde));
	} else {
		mut_res->p4d_base_phys = mut_res->pgd_base_phys;
	}
	mut_res->p4d_val = p4d_val(p4de);
	mut_res->p4d_readback = read_entry_phys(mut_res->p4d_base_phys +
						(mut_res->p4d_idx * ENTRY_SIZE));

	if (p4d_none(p4de) != 0) {
		return "P4D entry empty";
	}

	if (p4d_leaf(p4de)) {
		/* See the pud_leaf() note: gate residency via pte_present() mirror. */
		if (!is_entry_present(p4d_val(p4de))) {
			return "P4D huge entry not present (swap/migration)";
		}
		set_leaf(mut_res, vaddr, pw_arch_extract_table_phys(p4d_val(p4de)),
			 p4d_leaf_size(p4de), PW_LEAF_P4D, false);
		if (mut_mm_nullable != NULL) {
			spin_lock(&mut_mm_nullable->page_table_lock);
		}
		*mut_pin = pw_pin_frame(mut_res->final_phys_addr);

		p4d_t cur = p4dp_get(p4d);

		if (!p4d_leaf(cur) || !is_entry_present(p4d_val(cur)) ||
		    (pw_arch_extract_table_phys(p4d_val(cur)) !=
		     pw_arch_extract_table_phys(p4d_val(p4de)))) {
			pw_unpin(mut_pin);
		}
		if (mut_mm_nullable != NULL) {
			spin_unlock(&mut_mm_nullable->page_table_lock);
		}
		read_physical_content(mut_res, *mut_pin, mut_mm_nullable != NULL);
		return "mapped via P4D-level huge page";
	}

	if (p4d_bad(p4de) != 0) {
		return "P4D entry bad";
	}

	mut_res->pud_idx = pud_index(vaddr);

	pud_t *pud = pw_get_pud_slot(p4d, vaddr);
	pud_t pude = pudp_get(pud);

	if (mut_res->paging_level >= PAGING_LEVEL_4) {
		mut_res->pud_base_phys = pw_arch_extract_table_phys(p4d_val(p4de));
	} else {
		mut_res->pud_base_phys = mut_res->p4d_base_phys;
	}
	mut_res->pud_val = pud_val(pude);
	mut_res->pud_readback = read_entry_phys(mut_res->pud_base_phys +
						(mut_res->pud_idx * ENTRY_SIZE));

	if (pud_none(pude) != 0) {
		return "PUD entry empty";
	}

	if (pud_leaf(pude)) {
		/*
		 * pud_leaf() reports a 1G mapping but says nothing about residency.
		 * Gate on is_entry_present() (a pte_present() mirror) so a swapped or
		 * migrating huge entry is rejected while a resident PROT_NONE / NUMA-
		 * balancing huge page stays valid.
		 */
		if (!is_entry_present(pud_val(pude))) {
			return "PUD huge entry not present (swap/migration)";
		}
		set_leaf(mut_res, vaddr, PFN_PHYS(pud_pfn(pude)),
			 pud_leaf_size(pude), PW_LEAF_PUD,
			 pud_leaf_size(pude) != PUD_SIZE);

		spinlock_t *ptl = NULL;

		if (mut_mm_nullable != NULL) {
			ptl = pud_lock(mut_mm_nullable, pud);
		}
		*mut_pin = pw_pin_frame(mut_res->final_phys_addr);

		pud_t cur = pudp_get(pud);

		if (!pud_leaf(cur) || !is_entry_present(pud_val(cur)) ||
		    pud_pfn(cur) != pud_pfn(pude)) {
			pw_unpin(mut_pin);
		}
		if (ptl != NULL) {
			spin_unlock(ptl);
		}
		read_physical_content(mut_res, *mut_pin, mut_mm_nullable != NULL);
		return "mapped via PUD-level huge page";
	}

	if (pud_bad(pude) != 0) {
		return "PUD entry bad";
	}

	mut_res->pmd_idx = pmd_index(vaddr);

	pmd_t *pmd = pmd_offset(pud, vaddr);
	pmd_t pmde = pmdp_get_lockless(pmd);

	mut_res->pmd_base_phys = pw_arch_extract_table_phys(pud_val(pude));
	mut_res->pmd_val = pmd_val(pmde);
	mut_res->pmd_readback = read_entry_phys(mut_res->pmd_base_phys +
						(mut_res->pmd_idx * ENTRY_SIZE));

	if (pmd_none(pmde) != 0) {
		return "PMD entry empty";
	}

	if (pmd_leaf(pmde)) {
		/* See the pud_leaf() note: present|protnone, mirroring pte_present(). */
		if (!is_entry_present(pmd_val(pmde))) {
			return "PMD huge entry not present (swap/migration)";
		}
		set_leaf(mut_res, vaddr, PFN_PHYS(pmd_pfn(pmde)),
			 pmd_leaf_size(pmde), PW_LEAF_PMD,
			 pmd_leaf_size(pmde) != PMD_SIZE);

		spinlock_t *ptl = NULL;

		/*
		 * A hugetlb PMD table may be shared and torn down by another mm
		 * outside our mmap lock, so its ptl is not safe to take: pin and
		 * re-read without it, as the kernel walk does.
		 */
		if (mut_mm_nullable != NULL && !is_hugetlb) {
			ptl = pmd_lock(mut_mm_nullable, pmd);
		}
		*mut_pin = pw_pin_frame(mut_res->final_phys_addr);

		pmd_t cur = pmdp_get(pmd);

		if (!pmd_leaf(cur) || !is_entry_present(pmd_val(cur)) ||
		    pmd_pfn(cur) != pmd_pfn(pmde)) {
			pw_unpin(mut_pin);
		}
		if (ptl != NULL) {
			spin_unlock(ptl);
		}
		read_physical_content(mut_res, *mut_pin, mut_mm_nullable != NULL);
		return "mapped via PMD-level huge page";
	}

	if (pmd_bad(pmde) != 0) {
		return "PMD entry bad";
	}

	mut_res->pte_idx = pte_index(vaddr);
	mut_res->pte_base_phys = pw_arch_extract_table_phys(pmd_val(pmde));

	pte_t pte_entry;

	if (mut_mm_nullable != NULL) {
		/*
		 * The PTE table can be retracted under us by khugepaged /
		 * MADV_COLLAPSE, which clears the pmd and RCU-frees the PTE page.
		 * The exported, RCU-safe pte_offset_map_lock() is unavailable to
		 * modules, so we take the PMD's own page-table lock (pmd_lock, an
		 * inline). That is a different lock from pte_offset_map_lock's
		 * PTE-page ptl, but collapse clears the pmd via pmdp_collapse_flush()
		 * while holding exactly this lock, so holding it and re-validating
		 * the pmd blocks the clear that would detach the PTE page. The PTE
		 * page's own ptl is then nested inside it, as retract_page_tables()
		 * does, so the snapshot and the frame pin are taken under the lock
		 * that serialises a zap of this PTE. 64-bit arches have no highmem,
		 * so pte_offset_kernel() needs no kmap.
		 */
		spinlock_t *pmd_ptl = pmd_lock(mut_mm_nullable, pmd);

		pmde = pmdp_get(pmd);
		if (pmd_none(pmde) != 0 || pmd_leaf(pmde) || pmd_bad(pmde) != 0) {
			spin_unlock(pmd_ptl);
			return "PMD changed during walk (collapse race)";
		}

		spinlock_t *ptl = pte_lockptr(mut_mm_nullable, pmd);

		if (ptl != pmd_ptl) {
			spin_lock_nested(ptl, SINGLE_DEPTH_NESTING);
		}

		pte_t *pte = pte_offset_kernel(pmd, vaddr);

		pte_entry = ptep_get(pte);
		/* Read back the PTE slot while the lock still pins the table. */
		mut_res->pte_readback = read_entry_phys(mut_res->pte_base_phys +
							(mut_res->pte_idx * ENTRY_SIZE));
		if (pte_present(pte_entry) != 0) {
			*mut_pin = pw_pin_frame(PFN_PHYS(pte_pfn(pte_entry)));
		}
		if (ptl != pmd_ptl) {
			spin_unlock(ptl);
		}
		spin_unlock(pmd_ptl);
	} else {
		/* Kernel walk: no collapse race, so read the leaf table directly. */
		pte_t *pte = pte_offset_kernel(pmd, vaddr);

		pte_entry = ptep_get(pte);
		mut_res->pte_readback = read_entry_phys(mut_res->pte_base_phys +
							(mut_res->pte_idx * ENTRY_SIZE));
		if (pte_present(pte_entry) != 0) {
			*mut_pin = pw_pin_frame(PFN_PHYS(pte_pfn(pte_entry)));

			pte_t cur = ptep_get(pte);

			if (pte_present(cur) == 0 || pte_pfn(cur) != pte_pfn(pte_entry)) {
				pw_unpin(mut_pin);
			}
		}
	}

	mut_res->pte_val = pte_val(pte_entry);

	/*
	 * Only a present entry maps real RAM. A non-none, non-present PTE is a
	 * swap / migration entry whose bits are NOT a PFN; pte_present() also
	 * keeps genuine PROT_NONE / NUMA-balancing pages (resident) as valid.
	 */
	if (pte_present(pte_entry) == 0) {
		return "PTE not present (swapped out or unmapped)";
	}

	/*
	 * pte_leaf_size() returns the base granule for an ordinary 4K PTE, but the
	 * full contiguous span for an arm64 cont-PTE (64K) or a riscv NAPOT leaf
	 * (64K). set_leaf() then rounds the base and widens the offset accordingly,
	 * so a contiguous mapping resolves the correct physical address even when
	 * the target offset lies above the base granule.
	 */
	u64 size = pte_leaf_size(pte_entry);

	set_leaf(mut_res, vaddr, PFN_PHYS(pte_pfn(pte_entry)), size, PW_LEAF_PTE,
		 size != PAGE_SIZE);
	read_physical_content(mut_res, *mut_pin, mut_mm_nullable != NULL);
	return (size != PAGE_SIZE) ? "mapped via PTE contiguous page" : "mapped via PTE 4K page";
}

/*
 * Walk a KERNEL virtual address. There is no task mm: we root the walk at the
 * arch kernel table (CR3 on x86-64, TTBR1_EL1 on arm64, satp on riscv) and take
 * no mm lock. Kernel mappings for text / rodata / linear map / page tables are
 * stable, so this is safe; a bogus address folds to an empty entry and stops.
 */
static int perform_kernel_walk(struct pagewalker_result *const mut_res)
{
	pgd_t *root = pw_arch_get_kernel_pgd();

	pw_set_geometry(mut_res);

	unsigned long vaddr = mut_res->target_vaddr;

	if (root == NULL) {
		mut_res->is_valid = 0;
		pr_info_ratelimited("kernel vaddr 0x%lx: rejected (kernel walk unsupported on this arm64 PA config)\n",
				    vaddr);
		return 0;
	}
	if ((long)pw_arch_untag_addr(vaddr) >= 0) {
		mut_res->is_valid = 0;
		pr_info_ratelimited("kernel vaddr 0x%lx: rejected (not a kernel address)\n", vaddr);
		return -EADDRNOTAVAIL;
	}

	struct folio *pin;
	const char *reason = pw_walk_levels(mut_res, &pin, NULL, root);

	pw_unpin(&pin);

	if (mut_res->is_valid != 0) {
		pr_info_ratelimited("kernel vaddr 0x%lx -> phys 0x%llx [%s]\n",
				    vaddr, mut_res->final_phys_addr, reason);
	} else {
		pr_info_ratelimited("kernel vaddr 0x%lx: walk stopped [%s]\n",
				    vaddr, reason);
	}
	return 0;
}

/*
 * Is this physical frame ordinary System RAM? page_is_ram() consults the iomem
 * resource map, so it returns false for device MMIO, firmware-reserved windows
 * and holes. We refuse those by default: reading a device register can have a
 * side effect, which is the one "irreversible" hazard a memory dump must not
 * trigger blindly. The caller opts back in with PW_READ_F_ALLOW_MMIO.
 */
static bool is_system_ram(u64 phys)
{
	return page_is_ram(PHYS_PFN(phys)) != 0;
}

int perform_page_walk(struct pagewalker_result *const mut_res, pid_t pid)
{
	/* Validate the request before acquiring any process resources. */
	if (pid <= 0 || (unsigned long)pid >= PID_MAX_LIMIT) {
		pr_info_ratelimited("pid %d: rejected (pid out of range)\n", pid);
		return -EINVAL;
	}

	pw_set_geometry(mut_res);

	unsigned long vaddr = mut_res->target_vaddr;

	if (!pw_arch_is_addr_representable(vaddr, mut_res->va_bits)) {
		pr_info_ratelimited("pid %d vaddr 0x%lx: rejected (non-canonical address)\n",
				    pid, vaddr);
		return -EADDRNOTAVAIL;
	}

	struct pid *pid_struct = find_get_pid(pid);
	if (pid_struct == NULL) {
		pr_info_ratelimited("pid %d: rejected (no such process)\n", pid);
		return -ESRCH;
	}

	struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);

	put_pid(pid_struct);
	pid_struct = NULL;
	if (task == NULL) {
		pr_info_ratelimited("pid %d: rejected (task exited)\n", pid);
		return -ESRCH;
	}

	struct mm_struct *mm = get_task_mm(task);

	put_task_struct(task);
	task = NULL;
	if (mm == NULL) {
		pr_info_ratelimited("pid %d: rejected (no mm: kernel thread or exiting)\n", pid);
		return -ESRCH;
	}

	mmap_read_lock(mm);

	struct folio *pin;
	const char *reason = pw_walk_levels(mut_res, &pin, mm, mm->pgd);

	if (mut_res->is_valid != 0) {
		pr_info_ratelimited("pid %d vaddr 0x%lx -> phys 0x%llx [%s]\n",
				    pid, vaddr, mut_res->final_phys_addr, reason);
	} else {
		pr_info_ratelimited("pid %d vaddr 0x%lx: walk stopped [%s]\n",
				    pid, vaddr, reason);
	}

	mmap_read_unlock(mm);
	pw_unpin(&pin);
	mmput(mm);
	mm = NULL;
	return 0;
}

/*
 * Bulk read (command 2). Copy up to mut_req->size bytes starting at
 * mut_req->vaddr, from either a process address space (mut_req->pid) or the
 * kernel (PW_READ_F_KERNEL), into the user buffer mut_req->ubuf. The run is
 * walked one page at a time because physical frames are contiguous only within
 * a leaf, and every read is fault-tolerant, so an unmapped page or a hole
 * truncates the run instead of faulting. Each page's physical frame is checked
 * against System RAM and a non-RAM (MMIO / reserved) frame is refused unless
 * PW_READ_F_ALLOW_MMIO is set. mut_req->info is filled with the full walk of the
 * START address.
 */
int perform_read(struct pagewalker_read_request *const mut_req)
{
	bool is_kernel = (mut_req->flags & PW_READ_F_KERNEL) != 0;
	struct mm_struct *mm = NULL;
	unsigned long vaddr = mut_req->vaddr;
	u64 size = mut_req->size;
	u64 done = 0;
	int ret = 0;

	mut_req->bytes_read = 0;
	mut_req->stopped = PW_STOP_OK;
	memset(&mut_req->info, 0, sizeof(mut_req->info));
	mut_req->info.target_vaddr = vaddr;

	/*
	 * Clamp to the per-call ceiling; the CLI loops for a larger dump. A direct
	 * ioctl caller learns it was clamped via PW_STOP_TOOBIG.
	 */
	if (size > PW_READ_MAX) {
		size = PW_READ_MAX;
		mut_req->stopped = PW_STOP_TOOBIG;
	}

	/* Resolve the target process address space (kernel mode needs none). */
	if (!is_kernel) {
		if (mut_req->pid == 0 || mut_req->pid >= PID_MAX_LIMIT) {
			return -EINVAL;
		}

		struct pid *pid_struct = find_get_pid((int)mut_req->pid);
		if (pid_struct == NULL) {
			return -ESRCH;
		}

		struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);

		put_pid(pid_struct);
		pid_struct = NULL;
		if (task == NULL) {
			return -ESRCH;
		}

		mm = get_task_mm(task);
		put_task_struct(task);
		task = NULL;
		if (mm == NULL) {
			return -ESRCH;
		}
	}

	/*
	 * Reject a non-representable start address for a process read, matching the
	 * single-address command (which returns -EADDRNOTAVAIL); reported here via
	 * PW_STOP_NONCANON so a caller sees the reason instead of a masked alias. A
	 * kernel read must name the high half: a user-half address would resolve
	 * through the caller's own tables (x86/riscv) or a bogus TTBR1 index (arm64).
	 */
	if (!is_kernel) {
		pw_set_geometry(&mut_req->info);
		if (!pw_arch_is_addr_representable(vaddr, mut_req->info.va_bits)) {
			mut_req->stopped = PW_STOP_NONCANON;
			goto out_put_mm;
		}
	} else if ((long)pw_arch_untag_addr(vaddr) >= 0) {
		mut_req->stopped = PW_STOP_NOTKERNEL;
		goto out_put_mm;
	}

	pgd_t *kernel_pgd = NULL;

	/* Full walk of the START address, for the report the CLI still prints. */
	if (is_kernel) {
		kernel_pgd = pw_arch_get_kernel_pgd();
		if (kernel_pgd == NULL) {
			ret = -EOPNOTSUPP;
			goto out_put_mm;
		}
		perform_kernel_walk(&mut_req->info);
	} else {
		struct folio *pin;

		mmap_read_lock(mm);
		pw_walk_levels(&mut_req->info, &pin, mm, mm->pgd);
		mmap_read_unlock(mm);
		pw_unpin(&pin);
	}

	if (size == 0) {
		goto out_put_mm;
	}

	u8 *bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (bounce == NULL) {
		ret = -ENOMEM;
		goto out_put_mm;
	}

	bool is_mmio_allowed = (mut_req->flags & PW_READ_F_ALLOW_MMIO) != 0;
	u8 __user *dst = (u8 __user *)((uintptr_t)mut_req->ubuf);

	while (done < size) {
		unsigned long cur = vaddr + done;
		unsigned long pgoff = cur & (PAGE_SIZE - 1);
		size_t chunk = min_t(u64, size - done, PAGE_SIZE - pgoff);

		/* Resolve this page's frame first, so the RAM gate can vet it. */
		struct pagewalker_result step = {
			.target_vaddr = cur
		};
		struct folio *pin;

		pw_set_geometry(&step);
		if (is_kernel) {
			pw_walk_levels(&step, &pin, NULL, kernel_pgd);
		} else {
			mmap_read_lock(mm);
			pw_walk_levels(&step, &pin, mm, mm->pgd);
			mmap_read_unlock(mm);
		}

		if (step.is_valid == 0) {
			pw_unpin(&pin);
			mut_req->stopped = PW_STOP_UNMAPPED;
			break;
		}
		if (!is_mmio_allowed && !is_system_ram(step.final_phys_addr)) {
			pw_unpin(&pin);
			mut_req->stopped = PW_STOP_MMIO;
			break;
		}

		bool has_faulted;

		if (is_kernel && !is_system_ram(step.final_phys_addr)) {
			/*
			 * Non-RAM frame, explicitly allowed: there is no page to pin,
			 * so read at the kernel VA (ioremap / fixmap); a fault is
			 * still caught here.
			 */
			has_faulted = copy_from_kernel_nofault(bounce, (void *)cur, chunk) != 0;
		} else {
			/*
			 * The frame is in the linear map (no highmem on 64-bit), so
			 * read the bytes through phys_to_virt of the resolved address.
			 * A process frame is read only while the walk's pin holds it;
			 * a kernel frame the walk could not pin (free page) is still
			 * read, and copy_from_kernel_nofault keeps a reserved region
			 * or a hole from faulting.
			 */
			bool can_read;

			if (pin != NULL) {
				can_read = pw_is_range_pinned(pin, step.final_phys_addr, chunk);
			} else {
				can_read = is_kernel &&
					   pfn_valid(PHYS_PFN(step.final_phys_addr)) != 0;
			}
			has_faulted = !can_read ||
				      copy_from_kernel_nofault(bounce,
							       phys_to_virt(step.final_phys_addr),
							       chunk) != 0;
		}
		pw_unpin(&pin);
		if (has_faulted) {
			mut_req->stopped = PW_STOP_FAULT;
			break;
		}

		if (copy_to_user(dst + done, bounce, chunk) != 0) {
			ret = -EFAULT;
			break;
		}

		done += chunk;
		cond_resched();
	}

	kfree(bounce);
	bounce = NULL;

out_put_mm:
	mut_req->bytes_read = done;
	if (mm != NULL) {
		mmput(mm);
		mm = NULL;
	}
	return ret;
}
