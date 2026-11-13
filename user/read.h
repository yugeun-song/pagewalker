#ifndef USER_READ_H
#define USER_READ_H

#include "../include/pagewalker_common.h"

/* Parse a size argument (decimal by default; 0x/0b prefix; K/M/G suffix). */
int parse_size(unsigned long long *const mut_out, const char *const text_nullable);

/* Parse a virtual address (hex, with or without a 0x prefix). */
int parse_vaddr(unsigned long long *const mut_out, const char *const text_nullable);

/* Human string for a PW_STOP_* early-termination code. */
const char *describe_stop_reason(unsigned int code);

/*
 * Drive command 2 to copy `size` bytes starting at `start` into `mut_buf_nullable`,
 * looping over the kernel's PW_READ_MAX per-call ceiling. The walk of the first
 * address is captured in *mut_info. A short return stops the loop; *mut_stopped
 * carries the PW_STOP_* code and *mut_got the number of bytes copied. Returns 0,
 * or a negative errno from the ioctl.
 */
int do_read(unsigned char *const mut_buf_nullable, unsigned long long *const mut_got,
            unsigned int *const mut_stopped, struct pagewalker_result *const mut_info, int fd,
            int is_kernel, int is_mmio_allowed, unsigned int pid, unsigned long long start,
            unsigned long long size);

#endif /* USER_READ_H */
