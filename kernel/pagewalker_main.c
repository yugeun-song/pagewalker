// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "pagewalker.h"

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

/* Command 1: resolve one address and report its single-u64 content. */
static long pagewalker_get_info(unsigned long arg)
{
	struct pagewalker_request req;
	u64 saved_vaddr;
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

MODULE_DESCRIPTION("Page Table Walker with Phys Verification (x86-64/arm64/riscv64)");
MODULE_AUTHOR("Yugeun Song");
MODULE_LICENSE("GPL");
