/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PAGEWALKER_KERNEL_INTERNAL_H
#define PAGEWALKER_KERNEL_INTERNAL_H

#include <linux/mm.h>
#include <linux/types.h>

#include "../include/pagewalker_common.h"

#define RET_SUCCESS 0
#define BIT_IS_SET  1
#define ENTRY_SIZE  8	/* page-table entry is 8 bytes on every 64-bit arch */

/*
 * Cross-file interface of the module. The walk engine lives in walk.c, the bulk
 * read in read.c, and the character device / ioctl glue in main.c.
 */

/* walk.c */
void pw_set_geometry(struct pagewalker_result *res);
const char *pw_walk_levels(struct mm_struct *mm, pgd_t *pgd_root,
			   struct pagewalker_result *res);
int perform_page_walk(pid_t pid, struct pagewalker_result *res);
int perform_kernel_walk(struct pagewalker_result *res);

/* read.c */
int perform_read(struct pagewalker_read_request *rr);

#endif /* PAGEWALKER_KERNEL_INTERNAL_H */
