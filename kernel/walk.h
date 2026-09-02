/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PAGEWALKER_KERNEL_WALK_H
#define PAGEWALKER_KERNEL_WALK_H

#include <linux/mm.h>
#include <linux/types.h>

#include "../include/pagewalker_common.h"

/*
 * Page-table walk engine (walk.c). Records the arch walk geometry, resolves a
 * virtual address to its physical translation, and reads each level back from
 * its physical slot. The walk is architecture-neutral and folds absent levels
 * transparently; perform_page_walk drives a process address space and
 * perform_kernel_walk the kernel's own, rooted at the arch kernel table.
 */
void pw_set_geometry(struct pagewalker_result *res);
const char *pw_walk_levels(struct mm_struct *mm, pgd_t *pgd_root,
			   struct pagewalker_result *res);
int perform_page_walk(pid_t pid, struct pagewalker_result *res);
int perform_kernel_walk(struct pagewalker_result *res);

/*
 * Bulk read (command 2), layered on the walk above: copy a run of bytes out of a
 * target address space, re-walking each page and vetting every frame as System
 * RAM. Fault-tolerant: a hole or unmapped page truncates the run.
 */
int perform_read(struct pagewalker_read_request *rr);

#endif /* PAGEWALKER_KERNEL_WALK_H */
