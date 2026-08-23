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
#include <linux/slab.h>
#include <linux/sched/task.h>

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

/*
 * Root of the kernel half. init_mm / swapper are not exported to modules, so we
 * read the hardware root instead. On x86-64 the kernel PGD entries are cloned
 * into every process's page table, so CR3's current value already resolves a
 * kernel VA; read_cr3_pa() masks off PCID / the PTI bit to yield the pure base.
 */
static pgd_t *arch_kernel_pgd(void)
{
	return (pgd_t *)__va(read_cr3_pa());
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

/*
 * Root of the kernel half. Unlike x86, the arm64 kernel table lives under
 * TTBR1_EL1 (swapper_pg_dir) and is NOT present in a task's TTBR0 pgd, so a
 * kernel VA cannot be resolved through mm->pgd. Read TTBR1_EL1 directly and
 * strip the ASID (bits [63:48]) and CnP (bit 0); the base is page-aligned for
 * the non-52-bit-PA configuration this module targets.
 */
static pgd_t *arch_kernel_pgd(void)
{
	u64 ttbr1 = read_sysreg(ttbr1_el1);

	return (pgd_t *)__va(ttbr1 & GENMASK_ULL(47, PAGE_SHIFT));
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
 * Root of the kernel half. riscv has one root for the whole address space, and
 * the kernel mappings are cloned into every process's page table, so the value
 * programmed into satp already resolves a kernel VA. satp.PPN is the root PPN.
 */
static pgd_t *arch_kernel_pgd(void)
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

/* Record the arch-global walk geometry (level count, page size, VA width). */
static void pw_set_geometry(struct pagewalker_result *res)
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
static const char *pw_walk_levels(struct mm_struct *mm, pgd_t *pgd_root,
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

static int perform_page_walk(pid_t pid, struct pagewalker_result *res)
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
		return -ESRCH;		/* kernel thread or exiting task: no mm */
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
static int perform_kernel_walk(struct pagewalker_result *res)
{
	unsigned long vaddr = res->target_vaddr;
	const char *reason;

	pw_set_geometry(res);
	reason = pw_walk_levels(NULL, arch_kernel_pgd(), res);

	if (res->is_valid)
		pr_info_ratelimited("kernel vaddr 0x%lx -> phys 0x%llx [%s]\n",
				    vaddr, res->final_phys_addr, reason);
	else
		pr_info_ratelimited("kernel vaddr 0x%lx: walk stopped [%s]\n",
				    vaddr, reason);
	return RET_SUCCESS;
}

/*
 * Is this physical frame ordinary System RAM? page_is_ram() consults the iomem
 * resource map, so it returns false for device MMIO, firmware-reserved windows
 * and holes. We refuse those by default: reading a device register can have a
 * side effect, which is the one "irreversible" hazard a memory dump must not
 * trigger blindly. The caller opts back in with PW_READ_F_ALLOW_MMIO.
 */
static bool phys_is_ram(u64 phys)
{
	return page_is_ram(PHYS_PFN(phys));
}

/*
 * Bulk read (command 2). Copy up to rr->size bytes starting at rr->vaddr, from
 * either a process address space (rr->pid) or the kernel (PW_READ_F_KERNEL),
 * into the user buffer rr->ubuf. The run is walked one page at a time because
 * physical frames are contiguous only within a leaf, and every read is
 * fault-tolerant, so an unmapped page or a hole truncates the run instead of
 * faulting. Each page's physical frame is checked against System RAM and a
 * non-RAM (MMIO / reserved) frame is refused unless PW_READ_F_ALLOW_MMIO is set.
 * rr->info is filled with the full walk of the START address.
 */
static int perform_read(struct pagewalker_read_request *rr)
{
	bool kernel = rr->flags & PW_READ_F_KERNEL;
	bool allow_mmio = rr->flags & PW_READ_F_ALLOW_MMIO;
	struct mm_struct *mm = NULL;
	pgd_t *kpgd = NULL;
	void __user *dst = (void __user *)(uintptr_t)rr->ubuf;
	unsigned long vaddr = rr->vaddr;
	u64 size = rr->size;
	u64 done = 0;
	u8 *bounce;
	int ret = RET_SUCCESS;

	rr->bytes_read = 0;
	rr->stopped = PW_STOP_OK;
	memset(&rr->info, 0, sizeof(rr->info));
	rr->info.target_vaddr = vaddr;

	/* Clamp to the per-call ceiling; the CLI loops for a larger dump. */
	if (size > PW_READ_MAX)
		size = PW_READ_MAX;

	/* Resolve the target process address space (kernel mode needs none). */
	if (!kernel) {
		struct task_struct *task;
		struct pid *pid_struct;

		if (rr->pid == 0 || rr->pid >= PID_MAX_LIMIT)
			return -EINVAL;
		pid_struct = find_get_pid(rr->pid);
		if (!pid_struct)
			return -ESRCH;
		task = get_pid_task(pid_struct, PIDTYPE_PID);
		put_pid(pid_struct);
		if (!task)
			return -ESRCH;
		mm = get_task_mm(task);
		put_task_struct(task);
		if (!mm)
			return -ESRCH;
	}

	/* Full walk of the START address, for the report the CLI still prints. */
	if (kernel) {
		kpgd = arch_kernel_pgd();
		perform_kernel_walk(&rr->info);
	} else {
		pw_set_geometry(&rr->info);
		mmap_read_lock(mm);
		pw_walk_levels(mm, mm->pgd, &rr->info);
		mmap_read_unlock(mm);
	}

	if (size == 0)
		goto out;

	bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce) {
		ret = -ENOMEM;
		goto out;
	}

	while (done < size) {
		unsigned long cur = vaddr + done;
		unsigned long pgoff = cur & (PAGE_SIZE - 1);
		size_t chunk = min_t(u64, size - done, PAGE_SIZE - pgoff);
		struct pagewalker_result step;

		/* Resolve this page's frame first, so the RAM gate can vet it. */
		memset(&step, 0, sizeof(step));
		step.target_vaddr = cur;
		pw_set_geometry(&step);
		if (kernel) {
			pw_walk_levels(NULL, kpgd, &step);
		} else {
			mmap_read_lock(mm);
			pw_walk_levels(mm, mm->pgd, &step);
			mmap_read_unlock(mm);
		}

		if (!step.is_valid) {
			rr->stopped = PW_STOP_UNMAPPED;
			break;
		}
		if (!allow_mmio && !phys_is_ram(step.final_phys_addr)) {
			rr->stopped = PW_STOP_MMIO;
			break;
		}

		if (kernel) {
			/*
			 * Read at the kernel VA: correct for the linear map, vmalloc,
			 * modules and vmemmap alike. The frame was vetted as RAM (or
			 * MMIO was explicitly allowed); a fault is still caught here.
			 */
			if (copy_from_kernel_nofault(bounce, (void *)cur, chunk)) {
				rr->stopped = PW_STOP_FAULT;
				break;
			}
		} else {
			/*
			 * The frame is in the linear map (no highmem on 64-bit), so
			 * read the bytes through phys_to_virt of the resolved address.
			 * pfn_valid + copy_from_kernel_nofault keep a reserved region
			 * or a hole from faulting.
			 */
			if (!pfn_valid(PHYS_PFN(step.final_phys_addr)) ||
			    copy_from_kernel_nofault(bounce,
						     phys_to_virt(step.final_phys_addr),
						     chunk)) {
				rr->stopped = PW_STOP_FAULT;
				break;
			}
		}

		if (copy_to_user(dst + done, bounce, chunk)) {
			ret = -EFAULT;
			break;
		}

		done += chunk;
		cond_resched();
	}

	kfree(bounce);

out:
	rr->bytes_read = done;
	if (mm)
		mmput(mm);
	return ret;
}

/* Command 1: resolve one address and report its single-u64 content. */
static long pagewalker_get_info(unsigned long arg)
{
	struct pagewalker_request req;
	__u64 saved_vaddr;
	int ret;

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

/* Command 2: copy a run of bytes and report the walk of its start address. */
static long pagewalker_read(unsigned long arg)
{
	struct pagewalker_read_request *rr;
	long ret;

	rr = kmalloc(sizeof(*rr), GFP_KERNEL);
	if (!rr)
		return -ENOMEM;

	if (copy_from_user(rr, (void __user *)arg, sizeof(*rr))) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * A negative return is a hard error (bad pid / no such task). A completed
	 * call returns 0; rr->bytes_read and rr->stopped report how far the run
	 * got, and rr->info carries the walk of the start address.
	 */
	ret = perform_read(rr);
	if (ret < 0)
		goto out;

	if (copy_to_user((void __user *)arg, rr, sizeof(*rr)))
		ret = -EFAULT;

out:
	kfree(rr);
	return ret;
}

static long pagewalker_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case PAGEWALKER_IOC_GET_INFO:
		return pagewalker_get_info(arg);
	case PAGEWALKER_IOC_READ:
		return pagewalker_read(arg);
	default:
		return -ENOTTY;
	}
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
