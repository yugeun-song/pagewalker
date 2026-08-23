#ifndef PAGEWALKER_USER_READ_H
#define PAGEWALKER_USER_READ_H

#include "../include/pagewalker_common.h"

/* Parse a size argument (decimal by default; 0x/0b prefix; K/M/G suffix). */
int parse_size(const char *s, unsigned long long *out);

/* Parse a virtual address (hex, with or without a 0x prefix). */
int parse_vaddr(const char *s, unsigned long long *out);

/* Human string for a PW_STOP_* early-termination code. */
const char *stop_reason(unsigned int code);

/*
 * Drive command 2 to copy `size` bytes starting at `start` into `buf`, looping
 * over the kernel's PW_READ_MAX per-call ceiling. The walk of the first address
 * is captured in *out_info. A short return stops the loop; *out_stopped carries
 * the PW_STOP_* code and *out_got the number of bytes copied. Returns 0, or a
 * negative errno from the ioctl.
 */
int do_read(int fd, int kernel, int allow_mmio, unsigned int pid,
            unsigned long long start, unsigned long long size, unsigned char *buf,
            unsigned long long *out_got, unsigned int *out_stopped,
            struct pagewalker_result *out_info);

#endif /* PAGEWALKER_USER_READ_H */
