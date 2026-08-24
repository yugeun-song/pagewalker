// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/pfn.h>
#include <linux/pgtable.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/threads.h>

#include "pagewalker.h"
#include "arch.h"

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
int perform_read(struct pagewalker_read_request *rr)
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
		if (!kpgd) {
			ret = -EOPNOTSUPP;
			goto out;
		}
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
