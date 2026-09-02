#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "read.h"

#define BASE_HEX 16

/* Human string for a PW_STOP_* early-termination code. */
const char *stop_reason(unsigned int code)
{
    switch (code) {
    case PW_STOP_UNMAPPED: return "a page in the range is not mapped";
    case PW_STOP_FAULT:    return "a read faulted (hole / reserved / bad frame)";
    case PW_STOP_NONCANON: return "address not representable";
    case PW_STOP_TOOBIG:   return "size exceeded the per-call maximum";
    case PW_STOP_MMIO:     return "a page is not System RAM (MMIO/reserved); pass --allow-mmio";
    default:               return "unknown";
    }
}

/*
 * Parse a size argument. Unlike the address (which is hex), a size is decimal by
 * default; an explicit 0x / 0b prefix switches base, and a K/M/G (optionally
 * KiB/MiB/GiB) suffix multiplies by a power of 1024. A leading sign, an empty
 * string, trailing junk, or an overflow is rejected.
 */
int parse_size(const char *s, unsigned long long *out)
{
    unsigned long long v;
    unsigned long long mult = 1;
    char *end;
    int base = 10;

    if (!s || !*s || *s == '-' || *s == '+' || isspace((unsigned char)*s)) {
        return -1;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    } else if (s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
        base = 2;
        s += 2;
    }
    if (!*s) {
        return -1;
    }

    errno = 0;
    v = strtoull(s, &end, base);
    if (errno != 0 || end == s) {
        return -1;
    }

    if (*end) {
        switch (toupper((unsigned char)*end)) {
        case 'K': mult = 1ULL << 10; break;
        case 'M': mult = 1ULL << 20; break;
        case 'G': mult = 1ULL << 30; break;
        default:  return -1;
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

    *out = v * mult;
    return 0;
}

/*
 * Parse a virtual address: hex (with or without a 0x prefix), as the tool has
 * always taken it. A leading sign or empty string is rejected so "-1" is not
 * silently wrapped to ULLONG_MAX.
 */
int parse_vaddr(const char *s, unsigned long long *out)
{
    unsigned long long v;
    char *end;

    if (!s || !*s || *s == '-' || *s == '+' || isspace((unsigned char)*s)) {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, BASE_HEX);
    if (errno != 0 || *end != '\0' || end == s) {
        return -1;
    }
    *out = v;
    return 0;
}

int do_read(int fd, int kernel, int allow_mmio, unsigned int pid,
            unsigned long long start, unsigned long long size, unsigned char *buf,
            unsigned long long *out_got, unsigned int *out_stopped,
            struct pagewalker_result *out_info)
{
    unsigned long long done = 0;
    int have_info = 0;

    do {
        struct pagewalker_read_request rr;
        unsigned long long chunk = size - done;

        if (chunk > PW_READ_MAX) {
            chunk = PW_READ_MAX;
        }

        memset(&rr, 0, sizeof(rr));
        rr.pid = pid;
        rr.flags = (kernel ? PW_READ_F_KERNEL : 0) |
                   (allow_mmio ? PW_READ_F_ALLOW_MMIO : 0);
        rr.vaddr = start + done;
        rr.size = chunk;
        rr.ubuf = (unsigned long long)(uintptr_t)(buf + done);

        if (ioctl(fd, PAGEWALKER_IOC_READ, &rr) < 0) {
            *out_got = done; /* report bytes already copied before the failure */
            return -errno;
        }

        if (!have_info) {
            *out_info = rr.info;
            have_info = 1;
        }
        done += rr.bytes_read;
        *out_stopped = rr.stopped;

        if (rr.bytes_read < chunk) { /* truncated by a hole / unmapped */
            break;
        }
    } while (done < size);

    *out_got = done;
    return 0;
}
