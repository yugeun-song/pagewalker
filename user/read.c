#include "read.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BASE_HEX 16

/* Human string for a PW_STOP_* early-termination code. */
const char *describe_stop_reason(unsigned int code)
{
    switch (code) {
    case PW_STOP_UNMAPPED:
        return "a page in the range is not mapped";
    case PW_STOP_FAULT:
        return "a read faulted (hole / reserved / bad frame)";
    case PW_STOP_NONCANON:
        return "address not representable";
    case PW_STOP_TOOBIG:
        return "size exceeded the per-call maximum";
    case PW_STOP_MMIO:
        return "a page is not System RAM (MMIO/reserved); pass --allow-mmio";
    case PW_STOP_NOTKERNEL:
        return "not a kernel address";
    default:
        return "unknown";
    }
}

/*
 * Parse a size argument. Unlike the address (which is hex), a size is decimal by
 * default; an explicit 0x / 0b prefix switches base, and a K/M/G (optionally
 * KiB/MiB/GiB) suffix multiplies by a power of 1024. A leading sign, an empty
 * string, trailing junk, or an overflow is rejected.
 */
int parse_size(unsigned long long *const mut_out, const char *const text_nullable)
{
    if (text_nullable == NULL || text_nullable[0] == '\0' || text_nullable[0] == '-' ||
        text_nullable[0] == '+' || isspace((unsigned char)text_nullable[0]) != 0) {
        return -1;
    }

    const char *digits = text_nullable;
    int base = 10;

    if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits += 2;
    } else if (digits[0] == '0' && (digits[1] == 'b' || digits[1] == 'B')) {
        base = 2;
        digits += 2;
    }
    if (digits[0] == '\0') {
        return -1;
    }

    char *end = NULL;

    errno = 0;
    unsigned long long v = strtoull(digits, &end, base);
    if (errno != 0 || end == digits) {
        return -1;
    }

    unsigned long long mult = 1;

    if (*end != '\0') {
        switch (toupper((unsigned char)*end)) {
        case 'K':
            mult = 1ULL << 10;
            break;
        case 'M':
            mult = 1ULL << 20;
            break;
        case 'G':
            mult = 1ULL << 30;
            break;
        default:
            return -1;
        }
        ++end;
        if (*end == 'i' || *end == 'I') { /* KiB style */
            ++end;
        }
        if (*end == 'b' || *end == 'B') {
            ++end;
        }
        if (*end != '\0') {
            return -1;
        }
    }
    if (v > ULLONG_MAX / mult) { /* overflow */
        return -1;
    }

    *mut_out = v * mult;
    return 0;
}

/*
 * Parse a virtual address: hex (with or without a 0x prefix), as the tool has
 * always taken it. A leading sign or empty string is rejected so "-1" is not
 * silently wrapped to ULLONG_MAX.
 */
int parse_vaddr(unsigned long long *const mut_out, const char *const text_nullable)
{
    if (text_nullable == NULL || text_nullable[0] == '\0' || text_nullable[0] == '-' ||
        text_nullable[0] == '+' || isspace((unsigned char)text_nullable[0]) != 0) {
        return -1;
    }

    char *end = NULL;

    errno = 0;
    unsigned long long v = strtoull(text_nullable, &end, BASE_HEX);
    if (errno != 0 || *end != '\0' || end == text_nullable) {
        return -1;
    }

    *mut_out = v;
    return 0;
}

int do_read(unsigned char *const mut_buf_nullable, unsigned long long *const mut_got,
            unsigned int *const mut_stopped, struct pagewalker_result *const mut_info, int fd,
            int is_kernel, int is_mmio_allowed, unsigned int pid, unsigned long long start,
            unsigned long long size)
{
    unsigned long long done = 0;
    int has_info = 0;

    do {
        struct pagewalker_read_request rr;
        unsigned long long chunk = size - done;

        if (chunk > PW_READ_MAX) {
            chunk = PW_READ_MAX;
        }

        memset(&rr, 0, sizeof(rr));
        rr.pid = pid;
        rr.flags = ((is_kernel != 0) ? PW_READ_F_KERNEL : 0) |
                   ((is_mmio_allowed != 0) ? PW_READ_F_ALLOW_MMIO : 0);
        rr.vaddr = start + done;
        rr.size = chunk;
        if (mut_buf_nullable != NULL) {
            rr.ubuf = (unsigned long long)((uintptr_t)(mut_buf_nullable + done));
        }

        if (ioctl(fd, PAGEWALKER_IOC_READ, &rr) < 0) {
            *mut_got = done; /* report bytes already copied before the failure */
            return -errno;
        }

        if (has_info == 0) {
            *mut_info = rr.info;
            has_info = 1;
        }
        done += rr.bytes_read;
        *mut_stopped = rr.stopped;

        if (rr.bytes_read < chunk) { /* truncated by a hole / unmapped */
            break;
        }
    } while (done < size);

    *mut_got = done;
    return 0;
}
