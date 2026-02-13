#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <linux/threads.h>

#include "../include/pagewalk_common.h"

/* --- Constants --- */
#define MASK_CANONICAL_48      0xFFFF000000000000ULL
#define MASK_CANONICAL_57      0xFE00000000000000ULL
#define SHIFT_SIGN_BIT_48      47
#define SHIFT_SIGN_BIT_57      56
#define RET_SUCCESS            0
#define BIT_IS_SET             1

MODULE_DESCRIPTION("x86-64 Page Table Walker with Phys Verification");
MODULE_AUTHOR("ArchGeek");
MODULE_LICENSE("GPL");

static long pagewalk_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations pagewalk_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pagewalk_ioctl,
};

static struct miscdevice pagewalk_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = PAGEWALK_DEVICE_NAME,
	.fops = &pagewalk_fops,
};

static unsigned long get_phys_mask(void)
{
	return PHYSICAL_PAGE_MASK;
}

static int is_canonical_address(unsigned long vaddr, int levels)
{
	unsigned long sign_bit;
	unsigned long upper_bits;
	unsigned long mask;
	unsigned long shift;

#ifdef CONFIG_X86_5LEVEL
	if (levels == PAGING_LEVEL_5) {
		shift = SHIFT_SIGN_BIT_57;
		mask = MASK_CANONICAL_57;
	} else {
		shift = SHIFT_SIGN_BIT_48;
		mask = MASK_CANONICAL_48;
	}
#else
	shift = SHIFT_SIGN_BIT_48;
	mask = MASK_CANONICAL_48;
#endif

	sign_bit = (vaddr >> shift) & 1;
	upper_bits = vaddr & mask;

	if (sign_bit)
		return (upper_bits == mask);
	else
		return (upper_bits == 0);
}

/* * Safe Physical Memory Reader 
 * Uses direct mapping (phys_to_virt) and handles faults.
 */
static void read_physical_content(struct pagewalk_result *res)
{
	void *kaddr;
	unsigned long val = 0;
	
	/* 1. Validate if PFN is valid system RAM */
	if (!pfn_valid(res->page_base_phys >> PAGE_SHIFT)) {
		/* If it's MMIO or invalid PFN, reading might hang or crash. 
		 * We skip reading for safety unless we map it differently. */
		res->value_at_phys = 0xDEADBEEFDEADBEEF; 
		return;
	}

	/* 2. Get Kernel Virtual Address (Direct Mapping) */
	kaddr = phys_to_virt(res->final_phys_addr);

	/* 3. Read Safely (Prevents Kernel Panic on bad access) */
	/* copy_from_kernel_nofault works like probe_kernel_read */
	if (copy_from_kernel_nofault(&val, kaddr, sizeof(unsigned long))) {
		res->value_at_phys = 0xFFFFFFFFFFFFFFFF; /* Fault Indicator */
	} else {
		res->value_at_phys = val;
	}
}

static int perform_page_walk(pid_t pid, struct pagewalk_result *res)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long vaddr = res->target_vaddr;
	unsigned long phys_mask = get_phys_mask();
	int ret = 0;

	if (pid < 0 || pid > PID_MAX_LIMIT)
		return -EINVAL;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) return -ESRCH;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task) return -ESRCH;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) return -EINVAL;

	if (!mmap_read_trylock(mm))
		mmap_read_lock(mm);

#ifdef CONFIG_X86_5LEVEL
	res->levels = pgtable_l5_enabled() ? PAGING_LEVEL_5 : PAGING_LEVEL_4;
#else
	res->levels = PAGING_LEVEL_4;
#endif

	if (!is_canonical_address(vaddr, res->levels)) {
		ret = -EADDRNOTAVAIL;
		goto out_unlock;
	}

	res->cr3_phys = virt_to_phys(mm->pgd);

	res->pgd_idx = pgd_index(vaddr);
	pgd = pgd_offset(mm, vaddr);
	res->pgd_base_phys = virt_to_phys(mm->pgd);
	res->pgd_val = pgd_val(*pgd);

	if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out_unlock;

	res->p4d_idx = p4d_index(vaddr);
	p4d = p4d_offset(pgd, vaddr);
	if (res->levels == PAGING_LEVEL_5)
		res->p4d_base_phys = pgd_val(*pgd) & phys_mask;
	else
		res->p4d_base_phys = res->pgd_base_phys;
	res->p4d_val = p4d_val(*p4d);

	if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out_unlock;

	res->pud_idx = pud_index(vaddr);
	pud = pud_offset(p4d, vaddr);
	res->pud_base_phys = p4d_val(*p4d) & phys_mask;
	res->pud_val = pud_val(*pud);

	if (pud_none(*pud) || pud_bad(*pud)) goto out_unlock;
	
	if (pud_leaf(*pud)) {
		res->page_base_phys = (pud_val(*pud) & phys_mask);
		res->final_phys_addr = res->page_base_phys + (vaddr & ~PUD_MASK);
		res->valid = BIT_IS_SET;
		read_physical_content(res); /* Verify */
		goto out_unlock; 
	}

	res->pmd_idx = pmd_index(vaddr);
	pmd = pmd_offset(pud, vaddr);
	res->pmd_base_phys = pud_val(*pud) & phys_mask;
	res->pmd_val = pmd_val(*pmd);

	if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out_unlock;

	if (pmd_leaf(*pmd)) {
		res->page_base_phys = (pmd_val(*pmd) & phys_mask);
		res->final_phys_addr = res->page_base_phys + (vaddr & ~PMD_MASK);
		res->valid = BIT_IS_SET;
		read_physical_content(res); /* Verify */
		goto out_unlock;
	}

	res->pte_idx = pte_index(vaddr);
	pte = pte_offset_kernel(pmd, vaddr);
	res->pte_base_phys = pmd_val(*pmd) & phys_mask;
	res->pte_val = pte_val(*pte);

	if (pte_none(*pte)) goto out_unlock;

	res->page_offset = vaddr & ~PAGE_MASK;
	res->page_base_phys = pte_pfn(*pte) << PAGE_SHIFT;
	res->final_phys_addr = res->page_base_phys | res->page_offset;
	res->valid = BIT_IS_SET;
	
	read_physical_content(res); /* Verify */

out_unlock:
	mmap_read_unlock(mm);
	mmput(mm);
	return ret;
}

static long pagewalk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pagewalk_request req;
	int ret;
	__u64 saved_vaddr;

	if (cmd != PAGEWALK_IOC_GET_INFO) return -ENOTTY;
	if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

	saved_vaddr = req.info.target_vaddr;
	memset(&req.info, 0, sizeof(req.info));
	req.info.target_vaddr = saved_vaddr;

	ret = perform_page_walk(req.pid, &req.info);
	
	if (ret < 0) {
		if (ret == -EINVAL || ret == -ESRCH || ret == -EADDRNOTAVAIL)
			return ret;
		req.info.valid = 0;
	}

	if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
	return RET_SUCCESS;
}

static int __init pagewalk_init(void) {
	if (misc_register(&pagewalk_device)) {
		pr_err("pagewalk: failed to register misc device\n");
		return -1;
	}
	return 0;
}

static void __exit pagewalk_exit(void) {
	misc_deregister(&pagewalk_device);
}

module_init(pagewalk_init);
module_exit(pagewalk_exit);
