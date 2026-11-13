/* SPDX-License-Identifier: 0BSD */
#ifndef KERNEL_WALK_H
#define KERNEL_WALK_H

#include <linux/types.h>

#include "../include/pagewalker_common.h"

/*
 * Page-table walk engine (walk.c). Records the arch walk geometry, resolves a
 * virtual address to its physical translation, and reads each level back from
 * its physical slot. The walk is architecture-neutral and folds absent levels
 * transparently; perform_page_walk drives a process address space and
 * perform_kernel_walk the kernel's own, rooted at the arch kernel table.
 */
int perform_page_walk(struct pagewalker_result *const mut_res, pid_t pid);

/*
 * Bulk read (command 2), layered on the walk above: copy a run of bytes out of a
 * target address space, re-walking each page and vetting every frame as System
 * RAM. Fault-tolerant: a hole or unmapped page truncates the run.
 */
int perform_read(struct pagewalker_read_request *const mut_req);

#endif /* KERNEL_WALK_H */
