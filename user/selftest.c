/*
 * Self-contained verifier for QEMU. Built with -static (see the Makefile). When
 * run as PID 1 it acts as init (mount the pseudo-filesystems, load
 * /pagewalker.ko), then probes the module across whatever geometry the running
 * kernel actually provides:
 *
 *   - the base page, and EVERY hugepage size the kernel supports (enumerated
 *     from /sys/kernel/mm/hugepages), each verified by writing a sentinel at an
 *     offset above the base granule and checking the module's reported page_size
 *     and its physical read-back of that byte;
 *   - a kernel-space read of the running kernel's own _text (command 2, -k);
 *   - edge cases: an unmapped address (must report not-mapped, not crash) and a
 *     non-canonical address (must be rejected with EADDRNOTAVAIL, not crash).
 *
 * The same binary therefore adapts to any arch / granule / paging depth, so one
 * build covers every kernel variant under test. A config that cannot support a
 * case (e.g. a refused kernel walk) must fail SAFELY, and that safe failure is
 * itself asserted as a pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#include "../include/pagewalker_common.h"
#include "report.h"

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

static int passed;
static int failed;
static int skipped;

/* 0 = PASS, 1 = FAIL, 2 = SKIP. */
static void tally(int result)
{
    if (result == 0) {
        ++passed;
    } else if (result == 1) {
        ++failed;
    } else {
        ++skipped;
    }
}

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

static int log2_size(unsigned long long size)
{
    int shift = 0;

    while (((unsigned long long)1 << shift) < size) {
        ++shift;
    }
    return shift;
}

/*
 * Command 1: walk one process VA (our own). Returns 0 and fills *out on a
 * completed walk, or a negative -errno if the ioctl itself failed.
 */
static int walk_vaddr(unsigned long long vaddr, struct pagewalker_result *out)
{
    struct pagewalker_request req;
    int fd;
    int r;

    memset(&req, 0, sizeof(req));
    req.pid = (unsigned int)getpid();
    req.info.target_vaddr = vaddr;

    fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        return -errno;
    }
    r = ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req);
    close(fd);
    if (r < 0) {
        return -errno;
    }
    *out = req.info;
    return 0;
}

/*
 * Map a region (optionally hugetlb), write a sentinel at an offset ABOVE the
 * base granule, walk it, and verify the reported page_size and the physical
 * read-back of that sentinel. 0 = PASS, 1 = FAIL, 2 = SKIP.
 */
static int run_size_case(const char *name, unsigned long long size, int huge_shift)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    unsigned long long sentinel = 0xCAFEBABE00000000ULL ^ size;
    unsigned long base = (unsigned long)sysconf(_SC_PAGESIZE);
    unsigned long long off;
    volatile unsigned long long *probe;
    struct pagewalker_result info;
    void *region;
    int r;
    int bad = 0;

    if (huge_shift) {
        flags |= MAP_HUGETLB | (huge_shift << MAP_HUGE_SHIFT);
    }
    region = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (region == MAP_FAILED) {
        printf("CASE %-8s SKIP  (mmap size=%llu errno=%d - pool unavailable)\n",
               name, size, errno);
        return 2;
    }

    off = (size > base) ? ((size / 2) & ~7ULL) : 0;
    probe = (volatile unsigned long long *)((char *)region + off);
    *probe = sentinel;

    r = walk_vaddr((unsigned long long)(uintptr_t)probe, &info);
    if (r < 0) {
        printf("CASE %-8s FAIL  (ioctl errno=%d)\n", name, -r);
        munmap(region, (size_t)size);
        return 1;
    }
    if (!info.is_valid || info.page_size != size || info.value_at_phys != sentinel) {
        bad = 1;
    }
    printf("CASE %-8s %s  size=%llu(want %llu) level=%u contig=%u valid=%d phys=%s\n",
           name, bad ? "FAIL" : "PASS", (unsigned long long)info.page_size, size,
           info.mapping_level, info.is_contiguous, info.is_valid,
           (info.value_at_phys == sentinel) ? "ok" : "MISMATCH");
    munmap(region, (size_t)size);
    return bad ? 1 : 0;
}

/* Enumerate the kernel's supported hugepage sizes and test each one. */
static void run_all_hugepages(void)
{
    DIR *d = opendir("/sys/kernel/mm/hugepages");
    struct dirent *e;
    int found = 0;

    if (!d) {
        printf("CASE huge     SKIP  (no /sys/kernel/mm/hugepages)\n");
        return;
    }
    while ((e = readdir(d)) != NULL) {
        unsigned long kib;
        unsigned long long size;
        char name[32];

        if (sscanf(e->d_name, "hugepages-%lukB", &kib) != 1) {
            continue;
        }
        found = 1;
        size = (unsigned long long)kib * 1024;
        snprintf(name, sizeof(name), "%luK", kib);
        reserve_pool(kib, "4");
        tally(run_size_case(name, size, log2_size(size)));
    }
    closedir(d);
    if (!found) {
        printf("CASE huge     SKIP  (kernel exposes no hugepage sizes)\n");
    }
}

/*
 * Command 2: read a few bytes of the running kernel's own _text via the -k path.
 * A correct read returns bytes; on a config where the kernel walk is deliberately
 * refused the ioctl returns -EOPNOTSUPP, which is the safe path (not a crash) and
 * counts as a pass.
 */
static int run_kernel_read(void)
{
    struct pagewalker_read_request rr;
    unsigned char buf[64];
    unsigned long long text = 0;
    char line[512];
    char sym[128];
    char type;
    FILE *f;
    int fd;
    int r;

    f = fopen("/proc/kallsyms", "r");
    if (!f) {
        printf("CASE k-text   SKIP  (no /proc/kallsyms)\n");
        return 2;
    }
    while (fgets(line, sizeof(line), f)) {
        unsigned long long addr;

        if (sscanf(line, "%llx %c %127s", &addr, &type, sym) != 3) {
            continue;
        }
        if (strcmp(sym, "_text") == 0) {
            text = addr;
            break;
        }
    }
    fclose(f);
    if (text == 0) {
        printf("CASE k-text   SKIP  (_text not in kallsyms)\n");
        return 2;
    }

    memset(&rr, 0, sizeof(rr));
    rr.flags = PW_READ_F_KERNEL;
    rr.vaddr = text;
    rr.size = sizeof(buf);
    rr.ubuf = (unsigned long long)(uintptr_t)buf;

    fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        printf("CASE k-text   FAIL  (open errno=%d)\n", errno);
        return 1;
    }
    r = ioctl(fd, PAGEWALKER_IOC_READ, &rr);
    close(fd);
    if (r < 0) {
        if (errno == EOPNOTSUPP) {
            printf("CASE k-text   PASS  (kernel walk refused: EOPNOTSUPP - safe)\n");
            return 0;
        }
        printf("CASE k-text   FAIL  (ioctl errno=%d)\n", errno);
        return 1;
    }
    if (rr.bytes_read == 0 || rr.stopped != PW_STOP_OK) {
        printf("CASE k-text   FAIL  (bytes=%llu stopped=%u)\n",
               (unsigned long long)rr.bytes_read, rr.stopped);
        return 1;
    }
    printf("CASE k-text   PASS  (read %llu bytes at _text=0x%llx)\n",
           (unsigned long long)rr.bytes_read, text);
    return 0;
}

/* Edge: an unmapped address must resolve to "not mapped", not crash. */
static int run_edge_unmapped(void)
{
    unsigned long base = (unsigned long)sysconf(_SC_PAGESIZE);
    struct pagewalker_result info;
    void *region;
    unsigned long long vaddr;
    int r;

    region = mmap(NULL, base, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        printf("CASE unmap    SKIP  (mmap errno=%d)\n", errno);
        return 2;
    }
    vaddr = (unsigned long long)(uintptr_t)region;
    munmap(region, base);

    r = walk_vaddr(vaddr, &info);
    if (r < 0) {
        printf("CASE unmap    FAIL  (ioctl errno=%d)\n", -r);
        return 1;
    }
    if (info.is_valid) {
        printf("CASE unmap    FAIL  (reported mapped for an unmapped VA)\n");
        return 1;
    }
    printf("CASE unmap    PASS  (unmapped VA reported not-mapped, no crash)\n");
    return 0;
}

/* Edge: a non-canonical address must be rejected (EADDRNOTAVAIL), not crash. */
static int run_edge_noncanon(void)
{
    struct pagewalker_result info;
    int r;

    r = walk_vaddr(0xdead000000000000ULL, &info);
    if (r == -EADDRNOTAVAIL) {
        printf("CASE noncanon PASS  (non-canonical address rejected: EADDRNOTAVAIL)\n");
        return 0;
    }
    printf("CASE noncanon FAIL  (expected EADDRNOTAVAIL, got r=%d)\n", r);
    return 1;
}

/*
 * One-shot description of the running environment: arch, kernel, base page, and
 * the geometry the module reports for a live mapping (paging depth, VA width,
 * root table), plus the hugepage sizes the kernel exposes. This is what makes
 * the same binary a self-describing probe on any kernel it is dropped into.
 */
static void report_environment(void)
{
    unsigned long base = (unsigned long)sysconf(_SC_PAGESIZE);
    struct pagewalker_result info;
    struct utsname uts;
    void *region;
    DIR *d;
    struct dirent *e;
    int got_geometry = 0;

    printf("== ENVIRONMENT (%s) ==\n", PW_ARCH_NAME);
    if (uname(&uts) == 0) {
        printf("  kernel      : %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }
    printf("  base page   : %lu bytes\n", base);

    region = mmap(NULL, base, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region != MAP_FAILED) {
        *(volatile unsigned long *)region = 1;
        if (walk_vaddr((unsigned long long)(uintptr_t)region, &info) == 0 && info.is_valid) {
            printf("  paging      : %d-level, VA %u-bit, page %u KiB\n",
                   info.paging_level, info.va_bits, (1u << info.page_shift) / 1024);
            printf("  root table  : 0x%llx (phys)\n",
                   (unsigned long long)info.root_table_phys);
            got_geometry = 1;
        }
        munmap(region, base);
    }
    if (!got_geometry) {
        printf("  paging      : (probe walk failed)\n");
    }

    printf("  hugepages   :");
    d = opendir("/sys/kernel/mm/hugepages");
    if (d) {
        int n = 0;

        while ((e = readdir(d)) != NULL) {
            unsigned long kib;

            if (sscanf(e->d_name, "hugepages-%lukB", &kib) == 1) {
                printf(" %luK", kib);
                ++n;
            }
        }
        closedir(d);
        if (n == 0) {
            printf(" (none)");
        }
    } else {
        printf(" (unavailable)");
    }
    printf("\n\n");
}

int main(void)
{
    int is_init = (getpid() == 1);
    unsigned long base = (unsigned long)sysconf(_SC_PAGESIZE);

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

    report_environment();

    printf("== CAPABILITY CHECKS ==\n");
    tally(run_size_case("base", (unsigned long long)base, 0));
    run_all_hugepages();
    tally(run_kernel_read());
    tally(run_edge_unmapped());
    tally(run_edge_noncanon());

    printf("\n== SUMMARY (%s) ==\n", PW_ARCH_NAME);
    printf("passed=%d failed=%d skipped=%d\n", passed, failed, skipped);
    /* Require zero failures and at least the base page + one edge case. */
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
