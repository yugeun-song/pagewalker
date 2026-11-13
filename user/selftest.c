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

#define _DEFAULT_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "../include/pagewalker_common.h"
#include "report.h"

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
# define MAP_HUGE_SHIFT 26
#endif

static int gs_passed;
static int gs_failed;
static int gs_skipped;

/* 0 = PASS, 1 = FAIL, 2 = SKIP. */
static void tally(int result)
{
    if (result == 0) {
        ++gs_passed;
    } else if (result == 1) {
        ++gs_failed;
    } else {
        ++gs_skipped;
    }
}

static int load_module(const char *const path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    long status = syscall(SYS_finit_module, fd, "", 0);
    int saved_errno = errno;

    close(fd);
    errno = saved_errno;
    return (int)status;
}

/* Best-effort hugetlb pool reservation; a size the arch can't back just fails. */
static void reserve_pool(unsigned long kib, const char *const count)
{
    char path[128];

    snprintf(path, sizeof(path),
             "/sys/kernel/mm/hugepages/hugepages-%lukB/nr_hugepages", kib);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return;
    }
    /* ignore: the case mmap will SKIP if the pool stays empty */
    write(fd, count, strlen(count));
    close(fd);
}

static int compute_log2_size(unsigned long long size)
{
    int shift = 0;

    while (((unsigned long long)1 << shift) < size) {
        ++shift;
    }
    return shift;
}

/*
 * Command 1: walk one process VA (our own). Returns 0 and fills *mut_out on a
 * completed walk, or a negative -errno if the ioctl itself failed.
 */
static int walk_vaddr(struct pagewalker_result *const mut_out, unsigned long long vaddr)
{
    struct pagewalker_request req;

    memset(&req, 0, sizeof(req));
    req.pid = (unsigned int)getpid();
    req.info.target_vaddr = vaddr;

    int fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    int status = ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req);
    int saved_errno = errno;

    close(fd);
    if (status < 0) {
        return -saved_errno;
    }
    *mut_out = req.info;
    return 0;
}

/*
 * Map a region (optionally hugetlb), write a sentinel at an offset ABOVE the
 * base granule, walk it, and verify the reported page_size and the physical
 * read-back of that sentinel. 0 = PASS, 1 = FAIL, 2 = SKIP.
 */
static int run_size_case(const char *const name, unsigned long long size, int huge_shift)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (huge_shift != 0) {
        flags |= MAP_HUGETLB | (huge_shift << MAP_HUGE_SHIFT);
    }

    void *region = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (region == MAP_FAILED) {
        printf("CASE %-8s SKIP  (mmap size=%llu errno=%d - pool unavailable)\n",
               name, size, errno);
        return 2;
    }

    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    unsigned long long offset = (size > page_size) ? ((size / 2) & ~7ULL) : 0;
    volatile unsigned long long *probe = (volatile unsigned long long *)((char *)region + offset);
    unsigned long long sentinel = 0xCAFEBABE00000000ULL ^ size;

    *probe = sentinel;

    struct pagewalker_result info;
    int status = walk_vaddr(&info, (unsigned long long)((uintptr_t)probe));
    if (status < 0) {
        printf("CASE %-8s FAIL  (ioctl errno=%d)\n", name, -status);
        munmap(region, (size_t)size);
        region = NULL;
        probe = NULL;
        return 1;
    }

    int is_bad = 0;

    if (info.is_valid == 0 || info.page_size != size || info.value_at_phys != sentinel) {
        is_bad = 1;
    }
    printf("CASE %-8s %s  size=%llu(want %llu) level=%u contig=%u valid=%d phys=%s\n",
           name, (is_bad != 0) ? "FAIL" : "PASS", (unsigned long long)info.page_size, size,
           info.mapping_level, info.is_contiguous, info.is_valid,
           (info.value_at_phys == sentinel) ? "ok" : "MISMATCH");
    munmap(region, (size_t)size);
    region = NULL;
    probe = NULL;
    return (is_bad != 0) ? 1 : 0;
}

/* Enumerate the kernel's supported hugepage sizes and test each one. */
static void run_all_hugepages(void)
{
    DIR *dir = opendir("/sys/kernel/mm/hugepages");
    if (dir == NULL) {
        printf("CASE huge     SKIP  (no /sys/kernel/mm/hugepages)\n");
        return;
    }

    int has_found = 0;

    for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
        unsigned long kib;

        if (sscanf(entry->d_name, "hugepages-%lukB", &kib) != 1) {
            continue;
        }
        has_found = 1;

        unsigned long long size = (unsigned long long)kib * 1024;
        char name[32];

        snprintf(name, sizeof(name), "%luK", kib);
        reserve_pool(kib, "4");
        tally(run_size_case(name, size, compute_log2_size(size)));
    }
    closedir(dir);
    dir = NULL;
    if (has_found == 0) {
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
    FILE *file = fopen("/proc/kallsyms", "r");
    if (file == NULL) {
        printf("CASE k-text   SKIP  (no /proc/kallsyms)\n");
        return 2;
    }

    char line[512];
    unsigned long long text_addr = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long addr;
        char type;
        char symbol[128];

        if (sscanf(line, "%llx %c %127s", &addr, &type, symbol) != 3) {
            continue;
        }
        if (strcmp(symbol, "_text") == 0) {
            text_addr = addr;
            break;
        }
    }
    fclose(file);
    file = NULL;
    if (text_addr == 0) {
        printf("CASE k-text   SKIP  (_text not in kallsyms)\n");
        return 2;
    }

    struct pagewalker_read_request request;
    unsigned char buf[64];

    memset(&request, 0, sizeof(request));
    request.flags = PW_READ_F_KERNEL;
    request.vaddr = text_addr;
    request.size = sizeof(buf);
    request.ubuf = (unsigned long long)((uintptr_t)buf);

    int fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        printf("CASE k-text   FAIL  (open errno=%d)\n", errno);
        return 1;
    }

    int status = ioctl(fd, PAGEWALKER_IOC_READ, &request);
    int saved_errno = errno;

    close(fd);
    if (status < 0) {
        if (saved_errno == EOPNOTSUPP) {
            printf("CASE k-text   PASS  (kernel walk refused: EOPNOTSUPP - safe)\n");
            return 0;
        }
        printf("CASE k-text   FAIL  (ioctl errno=%d)\n", saved_errno);
        return 1;
    }
    if (request.bytes_read == 0 || request.stopped != PW_STOP_OK) {
        printf("CASE k-text   FAIL  (bytes=%llu stopped=%u)\n",
               (unsigned long long)request.bytes_read, request.stopped);
        return 1;
    }
    printf("CASE k-text   PASS  (read %llu bytes at _text=0x%llx)\n",
           (unsigned long long)request.bytes_read, text_addr);
    return 0;
}

/* Edge: an unmapped address must resolve to "not mapped", not crash. */
static int run_edge_unmapped(void)
{
    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    void *region = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        printf("CASE unmap    SKIP  (mmap errno=%d)\n", errno);
        return 2;
    }

    unsigned long long vaddr = (unsigned long long)((uintptr_t)region);

    munmap(region, page_size);
    region = NULL;

    struct pagewalker_result info;
    int status = walk_vaddr(&info, vaddr);
    if (status < 0) {
        printf("CASE unmap    FAIL  (ioctl errno=%d)\n", -status);
        return 1;
    }
    if (info.is_valid != 0) {
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
    int status = walk_vaddr(&info, 0xDEAD000000000000ULL);

    if (status == -EADDRNOTAVAIL) {
        printf("CASE noncanon PASS  (non-canonical address rejected: EADDRNOTAVAIL)\n");
        return 0;
    }
    printf("CASE noncanon FAIL  (expected EADDRNOTAVAIL, got r=%d)\n", status);
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
    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    struct utsname uts;

    printf("== ENVIRONMENT (%s) ==\n", PW_ARCH_NAME);
    if (uname(&uts) == 0) {
        printf("  kernel      : %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }
    printf("  base page   : %lu bytes\n", page_size);

    int has_geometry = 0;
    void *region = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (region != MAP_FAILED) {
        struct pagewalker_result info;

        *(volatile unsigned long *)region = 1;
        if (walk_vaddr(&info, (unsigned long long)((uintptr_t)region)) == 0 &&
            info.is_valid != 0) {
            printf("  paging      : %d-level, VA %u-bit, page %u KiB\n",
                   info.paging_level, info.va_bits, (1U << info.page_shift) / 1024);
            printf("  root table  : 0x%llx (phys)\n",
                   (unsigned long long)info.root_table_phys);
            has_geometry = 1;
        }
        munmap(region, page_size);
        region = NULL;
    }
    if (has_geometry == 0) {
        printf("  paging      : (probe walk failed)\n");
    }

    printf("  hugepages   :");

    DIR *dir = opendir("/sys/kernel/mm/hugepages");
    if (dir != NULL) {
        size_t count = 0;

        for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
            unsigned long kib;

            if (sscanf(entry->d_name, "hugepages-%lukB", &kib) == 1) {
                printf(" %luK", kib);
                ++count;
            }
        }
        closedir(dir);
        dir = NULL;
        if (count == 0) {
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

    if (is_init != 0) {
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
            int console_fd = open("/dev/console", O_WRONLY);

            if (console_fd >= 0) {
                dup2(console_fd, 1);
                dup2(console_fd, 2);
                if (console_fd > 2) {
                    close(console_fd);
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

    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);

    tally(run_size_case("base", (unsigned long long)page_size, 0));
    run_all_hugepages();
    tally(run_kernel_read());
    tally(run_edge_unmapped());
    tally(run_edge_noncanon());

    printf("\n== SUMMARY (%s) ==\n", PW_ARCH_NAME);
    printf("passed=%d failed=%d skipped=%d\n", gs_passed, gs_failed, gs_skipped);
    /* Require zero failures and at least the base page + one edge case. */
    if (gs_failed == 0 && gs_passed >= 2) {
        printf("SELFTEST: ALL PASS (%s)\n", PW_ARCH_NAME);
    } else {
        printf("SELFTEST: FAIL (%s)\n", PW_ARCH_NAME);
    }

    fflush(stdout);
    if (is_init != 0) {
        sync();
        reboot(RB_POWER_OFF);
    }
    if (gs_failed == 0 && gs_passed >= 2) {
        return 0;
    }
    return EXIT_FAILURE;
}
