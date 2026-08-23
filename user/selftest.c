/*
 * Self-contained verifier for QEMU. Built with -static (see the Makefile). When
 * run as PID 1 it acts as init (mount the pseudo-filesystems, load
 * /pagewalker.ko), then in every case it walks one of its OWN mappings and
 * checks that the physical content the module read back equals the sentinel it
 * wrote. This exercises the exact ABI + report path the CLI uses, on whatever
 * arch it runs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>

#include "../include/pagewalker_common.h"
#include "report.h"

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

static int load_module(const char *path)
{
    int fd = open(path, O_RDONLY);
    long r;

    if (fd < 0) {
        return -1;
    }
    r = syscall(SYS_finit_module, fd, "", 0);
    close(fd);
    return (int)r;
}

/* One self-test case: map a region (optionally hugetlb), probe an offset. */
struct pw_case {
    const char *name;
    size_t map_size;
    int huge_shift;              /* 0 = base page; else log2(huge size) */
    size_t probe_off;            /* 8-aligned offset to write + walk */
    unsigned long long exp_size; /* expected page_size (0 = don't check) */
    unsigned int exp_level;      /* expected mapping_level (0 = don't check) */
    int exp_contig;              /* expected is_contiguous (-1 = don't check) */
};

/* Best-effort hugetlb pool reservation; a size the arch can't back just fails. */
static void reserve_pool(unsigned long kib, const char *count)
{
    char path[128];
    int fd;

    snprintf(path, sizeof(path),
             "/sys/kernel/mm/hugepages/hugepages-%lukB/nr_hugepages", kib);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        return;
    }
    if (write(fd, count, strlen(count)) < 0) {
        /* ignore: the case mmap will SKIP if the pool stays empty */
    }
    close(fd);
}

/* Returns 0 = PASS, 1 = FAIL, 2 = SKIP. */
static int run_case(const struct pw_case *c, unsigned long long sentinel)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    struct pagewalker_request req;
    char buf[BUFFER_SIZE];
    volatile unsigned long long *probe;
    void *base;
    int fd;
    int bad = 0;

    if (c->huge_shift) {
        flags |= MAP_HUGETLB | (c->huge_shift << MAP_HUGE_SHIFT);
    }

    base = mmap(NULL, c->map_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (base == MAP_FAILED) {
        printf("CASE %-4s: SKIP  (mmap len=%zu huge_shift=%d errno=%d - pool unavailable)\n",
               c->name, c->map_size, c->huge_shift, errno);
        return 2;
    }

    probe = (volatile unsigned long long *)((char *)base + c->probe_off);
    *probe = sentinel; /* fault in + write the sentinel at the probed offset */

    memset(&req, 0, sizeof(req));
    req.pid = (unsigned int)getpid();
    req.info.target_vaddr = (unsigned long long)(uintptr_t)probe;

    fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        printf("CASE %-4s: FAIL  (open %s errno=%d)\n", c->name, PAGEWALKER_PATH, errno);
        munmap(base, c->map_size);
        return 1;
    }
    if (ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req) < 0) {
        printf("CASE %-4s: FAIL  (ioctl errno=%d)\n", c->name, errno);
        close(fd);
        munmap(base, c->map_size);
        return 1;
    }
    close(fd);

    build_report(buf, &req.info, req.pid, 0);
    printf("%s", buf);

    if (!req.info.is_valid) {
        bad = 1;
    }
    if (req.info.value_at_phys != sentinel) {
        bad = 1; /* the probed offset's physical address must be correct */
    }
    if (c->exp_size && req.info.page_size != c->exp_size) {
        bad = 1;
    }
    if (c->exp_level && req.info.mapping_level != c->exp_level) {
        bad = 1;
    }
    if (c->exp_contig >= 0 && (int)req.info.is_contiguous != c->exp_contig) {
        bad = 1;
    }

    printf("CASE %-4s: %s  off=0x%zx size=%llu level=%u contig=%u valid=%d phys=%s"
           "  (want size=%llu level=%u contig=%d)\n",
           c->name, bad ? "FAIL" : "PASS", c->probe_off,
           (unsigned long long)req.info.page_size, req.info.mapping_level,
           req.info.is_contiguous, req.info.is_valid,
           (req.info.value_at_phys == sentinel) ? "ok" : "MISMATCH",
           c->exp_size, c->exp_level, c->exp_contig);

    munmap(base, c->map_size);
    return bad ? 1 : 0;
}

int main(void)
{
    int is_init = (getpid() == 1);
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    size_t i;

    const struct pw_case cases[] = {
        /* name  map_size       huge  probe_off    exp_size    exp_level    contig */
        {"4K", ps, 0, 0, (unsigned long long)ps, PW_LEAF_PTE, 0},
        {"64K", (size_t)1 << 16, 16, 0x9000, 1ULL << 16, PW_LEAF_PTE, 1},
        {"2M", (size_t)1 << 21, 21, 0x150000, 1ULL << 21, PW_LEAF_PMD, 0},
        {"1G", (size_t)1 << 30, 30, 0x20000000, 1ULL << 30, PW_LEAF_PUD, 0},
    };

    if (is_init) {
        mkdir("/proc", 0755);
        mkdir("/sys", 0755);
        mkdir("/dev", 0755);
        mount("proc", "/proc", "proc", 0, NULL);
        mount("sysfs", "/sys", "sysfs", 0, NULL);
        mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
        /*
         * Bind stdout/stderr to the serial console. An initramfs has no device
         * nodes until devtmpfs is mounted (just above), so the kernel may have
         * failed to open an initial console for PID 1; without this the report
         * would never reach the QEMU serial log.
         */
        {
            int cfd = open("/dev/console", O_WRONLY);

            if (cfd >= 0) {
                dup2(cfd, 1);
                dup2(cfd, 2);
                if (cfd > 2) {
                    close(cfd);
                }
            }
        }
        if (load_module("/pagewalker.ko") != 0) {
            printf("SELFTEST: finit_module(/pagewalker.ko) failed errno=%d\n", errno);
        } else {
            printf("SELFTEST: module loaded\n");
        }
    }

    /* 64K = arm64 cont-PTE / riscv NAPOT; 2M = PMD; 1G = PUD (boot-reserved). */
    reserve_pool(64, "16");
    reserve_pool(2048, "16");
    reserve_pool(1048576, "1");

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int r = run_case(&cases[i], 0xCAFEBABEDEADBEEFULL + i);

        if (r == 0) {
            ++passed;
        } else if (r == 1) {
            ++failed;
        } else {
            ++skipped;
        }
    }

    printf("\nSELFTEST SUMMARY (%s): passed=%d failed=%d skipped=%d\n",
           PW_ARCH_NAME, passed, failed, skipped);
    /* Require the always-available cases (4K + 2M) and zero failures. */
    if (failed == 0 && passed >= 2) {
        printf("SELFTEST: ALL PASS (%s)\n", PW_ARCH_NAME);
    } else {
        printf("SELFTEST: FAIL (%s)\n", PW_ARCH_NAME);
    }

    fflush(stdout);
    if (is_init) {
        sync();
        reboot(RB_POWER_OFF);
    }
    return (failed == 0 && passed >= 2) ? 0 : 1;
}
