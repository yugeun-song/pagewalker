/* SPDX-License-Identifier: 0BSD */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>

#include "walk.h"

/*
 * The command numbers carry the sizes of these structures, and the CLI reads
 * them field by field, so their layout is frozen and checked here.
 */
_Static_assert(sizeof(struct pagewalker_result) == 248, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, target_vaddr) == 0, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, paging_level) == 8, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, page_shift) == 12, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, va_bits) == 16, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, root_table_phys) == 24, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pgd_idx) == 32, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, p4d_idx) == 40, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pud_idx) == 48, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pmd_idx) == 56, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pte_idx) == 64, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, page_offset) == 72, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pgd_val) == 80, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, p4d_val) == 88, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pud_val) == 96, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pmd_val) == 104, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pte_val) == 112, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pgd_readback) == 120, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, p4d_readback) == 128, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pud_readback) == 136, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pmd_readback) == 144, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pte_readback) == 152, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pgd_base_phys) == 160, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, p4d_base_phys) == 168, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pud_base_phys) == 176, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pmd_base_phys) == 184, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, pte_base_phys) == 192, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, page_base_phys) == 200, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, final_phys_addr) == 208, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, page_size) == 216, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, mapping_level) == 224, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, is_contiguous) == 228, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, value_at_phys) == 232, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_result, is_valid) == 240, "pagewalker ABI layout");
_Static_assert(sizeof(struct pagewalker_request) == 256, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_request, pid) == 0, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_request, padding) == 4, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_request, info) == 8, "pagewalker ABI layout");
_Static_assert(sizeof(struct pagewalker_read_request) == 296, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, pid) == 0, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, flags) == 4, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, vaddr) == 8, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, size) == 16, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, ubuf) == 24, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, bytes_read) == 32, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, stopped) == 40, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, pad) == 44, "pagewalker ABI layout");
_Static_assert(offsetof(struct pagewalker_read_request, info) == 48, "pagewalker ABI layout");

static int pagewalker_open(struct inode *const inode, struct file *const file);
static long pagewalker_handle_ioctl(struct file *const file, unsigned int cmd, unsigned long arg);

static const struct file_operations gs_pagewalker_fops = {
	.owner = THIS_MODULE,
	.open = pagewalker_open,
	.unlocked_ioctl = pagewalker_handle_ioctl,
};

static struct miscdevice gs_pagewalker_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = PAGEWALKER_DEVICE_NAME,
	.fops = &gs_pagewalker_fops,
};

/* Command 1: resolve one address and report its single-u64 content. */
static long pagewalker_get_info(unsigned long arg)
{
	struct pagewalker_request req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0) {
		return -EFAULT;
	}

	/* Preserve the caller-supplied input; zero the rest of the result. */
	u64 saved_vaddr = req.info.target_vaddr;

	memset(&req.info, 0, sizeof(req.info));
	req.info.target_vaddr = saved_vaddr;

	/*
	 * A negative return is a hard error (bad pid / non-canonical address /
	 * no such task) reported via errno. A completed walk returns 0 with
	 * req.info.is_valid telling apart "mapped" from "not mapped".
	 */
	int ret = perform_page_walk(&req.info, (pid_t)req.pid);
	if (ret < 0) {
		return ret;
	}

	if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0) {
		return -EFAULT;
	}
	return 0;
}

/* Command 2: copy a run of bytes and report the walk of its start address. */
static long pagewalker_read(unsigned long arg)
{
	struct pagewalker_read_request *req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (req == NULL) {
		return -ENOMEM;
	}

	long ret;

	if (copy_from_user(req, (void __user *)arg, sizeof(*req)) != 0) {
		ret = -EFAULT;
		goto out_free_req;
	}

	/*
	 * A negative return is a hard error (bad pid / no such task). A completed
	 * call returns 0; req->bytes_read and req->stopped report how far the run
	 * got, and req->info carries the walk of the start address.
	 */
	ret = perform_read(req);
	if (ret < 0) {
		goto out_free_req;
	}

	if (copy_to_user((void __user *)arg, req, sizeof(*req)) != 0) {
		ret = -EFAULT;
	}

out_free_req:
	kfree(req);
	req = NULL;
	return ret;
}

static int pagewalker_open(struct inode *const inode, struct file *const file)
{
	return (capable(CAP_SYS_RAWIO)) ? 0 : -EPERM;
}

static long pagewalker_handle_ioctl(struct file *const file, unsigned int cmd, unsigned long arg)
{
	if (!capable(CAP_SYS_RAWIO)) {
		return -EPERM;
	}

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
	int ret = misc_register(&gs_pagewalker_device);

	if (ret != 0) {
		pr_err("failed to register misc device: %d\n", ret);
		return ret;
	}

	pr_info("loaded: /dev/%s ready (minor %d)\n",
		PAGEWALKER_DEVICE_NAME, gs_pagewalker_device.minor);
	return ret;
}

static void __exit pagewalker_exit(void)
{
	misc_deregister(&gs_pagewalker_device);
	pr_info("unloaded\n");
}

module_init(pagewalker_init);
module_exit(pagewalker_exit);

MODULE_DESCRIPTION("Page Table Walker with Phys Verification (x86-64/arm64/riscv64)");
MODULE_AUTHOR("Yugeun Song");
MODULE_LICENSE("Dual BSD/GPL");
