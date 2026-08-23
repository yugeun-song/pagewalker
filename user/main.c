#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../include/pagewalker_common.h"

#define BUFFER_SIZE          16384
#define PID_MAX_FILE         "/proc/sys/kernel/pid_max"
#define DEFAULT_PID_MAX      32768
#define BASE_DECIMAL         10
#define BASE_HEX             16

/* ------------------------------------------------------------------------- *
 * Architecture layer (user side)
 *
 * The report skeleton is shared; only three things are hardware-defined and
 * isolated per arch here: the arch / root-register names, the page-table entry
 * flag bits, and how those flags decode into a token list. The walk geometry
 * (level count, VA width, page size) is reported by the kernel at runtime, so
 * the address breakdown and the step list below are computed, not hardcoded.
 * ------------------------------------------------------------------------- */

#if defined(__x86_64__)
# define PW_ARCH_NAME      "x86-64"
# define PW_ROOT_REG_NAME  "CR3"
# define PW_CONT_TERM      "contiguous"
#elif defined(__aarch64__)
# define PW_ARCH_NAME      "arm64"
# define PW_ROOT_REG_NAME  "TTBR0_EL1"
# define PW_CONT_TERM      "ARM64 contiguous (cont-PTE/cont-PMD)"
#elif defined(__riscv) && (__riscv_xlen == 64)
# define PW_ARCH_NAME      "riscv64"
# define PW_ROOT_REG_NAME  "satp"
# define PW_CONT_TERM      "RISC-V NAPOT"
#else
# error "pagewalker: unsupported architecture (need x86-64, arm64, or riscv64)"
#endif

static inline void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [options] <pid> <address|symbol> [size]\n"
        "  %s [options] -k <symbol|0xaddr> [size]\n"
        "\n"
        "Walk the page tables for one address and, when a size is given, dump\n"
        "that many bytes of the mapped memory. For a process the target may be a\n"
        "hex address or the name of a global/static symbol in that process (a\n"
        "local/stack/heap variable has no symbol; pass its runtime %%p address).\n"
        "\n"
        "Options:\n"
        "  -k, --kernel        target the kernel address space; the first argument\n"
        "                      is a kernel symbol name (resolved via /proc/kallsyms)\n"
        "                      or a 0x-prefixed kernel address (e.g. _text, memblock,\n"
        "                      swapper_pg_dir)\n"
        "  -f, --format FMT    dump format: hex (default), raw, or cjk\n"
        "  -x, --hex           hexdump with an ASCII gutter (the default)\n"
        "  -c, --cjk           hexdump with a UTF-8 / CJK-aware text gutter\n"
        "  -r, --raw           raw bytes to stdout, for piping (refuses a TTY)\n"
        "  -F, --force         allow raw output even when stdout is a terminal\n"
        "  -w, --cols N        bytes per hexdump line (1..256, default 16)\n"
        "  -g, --group N       bytes per hex group; 0 disables grouping (default 8)\n"
        "  -u, --upper         uppercase hex digits\n"
        "      --no-report     print only the byte dump, not the walk report\n"
        "      --allow-mmio    permit reads of non-System-RAM (MMIO / reserved);\n"
        "                      by default such a page is refused to avoid device\n"
        "                      side effects\n"
        "  -h, --help          show this help\n"
        "\n"
        "size accepts decimal, 0x hex, 0b binary, and K/M/G suffixes (e.g. 256, 0x40, 2K).\n",
        prog_name, prog_name);
}

static unsigned int get_system_pid_max(void)
{
    FILE *f = fopen(PID_MAX_FILE, "r");
    unsigned int max = DEFAULT_PID_MAX;
    if (f) {
        if (fscanf(f, "%u", &max) != 1) {
            max = DEFAULT_PID_MAX;
        }
        fclose(f);
    }
    return max;
}

/* Append `s` to out[pos], not exceeding cap; returns the new length. */
static int append_str(char *out, int pos, int cap, const char *s)
{
    int i = 0;

    while (s[i] != '\0' && pos < cap - 1) {
        out[pos] = s[i];
        ++pos;
        ++i;
    }
    out[pos] = '\0';
    return pos;
}

/* One-line description of the root translation register for this arch. */
static void describe_root_reg(char *out, int cap, const struct pagewalker_result *res, int kernel)
{
#if defined(__x86_64__)
    (void)res;
    snprintf(out, cap,
        "CR3 holds the PGD/PML4 physical base; one root maps both the user and kernel halves.");
#elif defined(__aarch64__)
    (void)res;
    if (kernel)
        snprintf(out, cap,
            "TTBR1_EL1 holds the kernel (high-half) translation base; walked here for a kernel address.");
    else
        snprintf(out, cap,
            "TTBR0_EL1 = user (low-half) translation base; TTBR1_EL1 holds the kernel (high-half) base.");
#elif defined(__riscv)
    (void)kernel;
    int sv = res->paging_level == PAGING_LEVEL_5 ? 57 :
             res->paging_level == PAGING_LEVEL_4 ? 48 : 39;
    snprintf(out, cap,
        "satp: MODE=Sv%d, root PPN=0x%llx (phys >> %u); one root for the whole address space.",
        sv, (unsigned long long)(res->root_table_phys >> res->page_shift), res->page_shift);
#endif
}

/* Name of the root translation register actually used for this walk. */
static const char *root_reg_name(int kernel)
{
#if defined(__aarch64__)
    return kernel ? "TTBR1_EL1" : "TTBR0_EL1";
#else
    (void)kernel;
    return PW_ROOT_REG_NAME;
#endif
}

/*
 * Decode the flag bits of a present entry into a compact token list. The bit
 * layout is hardware-defined and disjoint across arches (only the present/valid
 * bit at bit 0 coincides), so this is the one decoder that must be per-arch.
 * `huge_capable` marks the PUD/PMD levels (block-capable); `is_pte` marks the
 * last level.
 */
#if defined(__x86_64__)

/* x86-64 entry flags (low 12 + NX). Bit 7 is PS at PMD/PUD, PAT at PTE. */
#define PTE_PRESENT          (1ULL << 0)
#define PTE_RW               (1ULL << 1)
#define PTE_USER             (1ULL << 2)
#define PTE_PWT              (1ULL << 3)
#define PTE_PCD              (1ULL << 4)
#define PTE_ACCESSED         (1ULL << 5)
#define PTE_DIRTY            (1ULL << 6)
#define PTE_PSE              (1ULL << 7)
#define PTE_GLOBAL           (1ULL << 8)
#define PTE_NX               (1ULL << 63)

static void decode_pte_flags(char *out, int cap, unsigned long long e,
                             int huge_capable, int is_pte)
{
    int leaf = is_pte || (huge_capable && (e & PTE_PSE));
    int p = 0;

    out[0] = '\0';
    p = append_str(out, p, cap, "P");
    p = append_str(out, p, cap, (e & PTE_RW) ? " RW" : " RO");
    p = append_str(out, p, cap, (e & PTE_USER) ? " U" : " S");

    if (e & PTE_ACCESSED)
        p = append_str(out, p, cap, " A");
    if (leaf && (e & PTE_DIRTY))
        p = append_str(out, p, cap, " D");
    if (e & PTE_PWT)
        p = append_str(out, p, cap, " PWT");
    if (e & PTE_PCD)
        p = append_str(out, p, cap, " PCD");
    if (e & PTE_GLOBAL)
        p = append_str(out, p, cap, " G");
    if (huge_capable && (e & PTE_PSE))
        p = append_str(out, p, cap, " PS");
    if (is_pte && (e & PTE_PSE))
        p = append_str(out, p, cap, " PAT");

    p = append_str(out, p, cap, (e & PTE_NX) ? " NX" : " X");
}

#elif defined(__aarch64__)

/* arm64 stage-1 descriptor attributes (4KB granule). */
#define A64_VALID            (1ULL << 0)
#define A64_TABLE            (1ULL << 1)   /* at PUD/PMD: 1=table, 0=block */
#define A64_ATTRINDX_SHIFT   2
#define A64_ATTRINDX_MASK    (7ULL << 2)   /* MAIR index */
#define A64_USER             (1ULL << 6)   /* AP[1]: 1=EL0 accessible */
#define A64_RDONLY           (1ULL << 7)   /* AP[2]: 1=read-only */
#define A64_SH_SHIFT         8
#define A64_SH_MASK          (3ULL << 8)   /* SH[1:0] shareability */
#define A64_AF               (1ULL << 10)  /* Access Flag (~ x86 Accessed) */
#define A64_NG               (1ULL << 11)  /* not-Global (inverse of x86 G) */
#define A64_DBM              (1ULL << 51)  /* Dirty Bit Management */
#define A64_CONT             (1ULL << 52)  /* Contiguous range */
#define A64_PXN              (1ULL << 53)  /* Privileged eXecute Never */
#define A64_UXN              (1ULL << 54)  /* User eXecute Never */

static void decode_pte_flags(char *out, int cap, unsigned long long e,
                             int huge_capable, int is_pte)
{
    unsigned sh = (unsigned)((e & A64_SH_MASK) >> A64_SH_SHIFT);
    char ai[16];
    int p = 0;

    (void)is_pte;
    out[0] = '\0';
    p = append_str(out, p, cap, "V");
    p = append_str(out, p, cap, (e & A64_RDONLY) ? " RO" : " RW");
    p = append_str(out, p, cap, (e & A64_USER) ? " U" : " S");
    if (e & A64_AF)
        p = append_str(out, p, cap, " AF");
    p = append_str(out, p, cap, (e & A64_NG) ? " nG" : " G");
    p = append_str(out, p, cap, sh == 3 ? " ISH" : sh == 2 ? " OSH" :
                                 sh == 0 ? " NSH" : " SH?");
    if (e & A64_CONT)
        p = append_str(out, p, cap, " Cont");
    if (e & A64_DBM)
        p = append_str(out, p, cap, " DBM");
    p = append_str(out, p, cap, (e & A64_PXN) ? " PXN" : " PX");
    p = append_str(out, p, cap, (e & A64_UXN) ? " UXN" : " UX");
    snprintf(ai, sizeof(ai), " AI=%u",
             (unsigned)((e & A64_ATTRINDX_MASK) >> A64_ATTRINDX_SHIFT));
    p = append_str(out, p, cap, ai);
    if (huge_capable && !(e & A64_TABLE))
        p = append_str(out, p, cap, " BLK");
}

#elif defined(__riscv)

/* riscv PTE flags: low 8 bits are V R W X U G A D; PPN starts at bit 10. */
#define RV_V                 (1ULL << 0)
#define RV_R                 (1ULL << 1)
#define RV_W                 (1ULL << 2)
#define RV_X                 (1ULL << 3)
#define RV_U                 (1ULL << 4)
#define RV_G                 (1ULL << 5)
#define RV_A                 (1ULL << 6)
#define RV_D                 (1ULL << 7)

static void decode_pte_flags(char *out, int cap, unsigned long long e,
                             int huge_capable, int is_pte)
{
    int p = 0;

    (void)huge_capable;
    (void)is_pte;
    out[0] = '\0';
    p = append_str(out, p, cap, "V");
    if (e & RV_R)
        p = append_str(out, p, cap, " R");
    if (e & RV_W)
        p = append_str(out, p, cap, " W");
    if (e & RV_X)
        p = append_str(out, p, cap, " X");
    p = append_str(out, p, cap, (e & RV_U) ? " U" : " S");
    if (e & RV_G)
        p = append_str(out, p, cap, " G");
    if (e & RV_A)
        p = append_str(out, p, cap, " A");
    if (e & RV_D)
        p = append_str(out, p, cap, " D");
    /* No R/W/X set means this is a pointer to the next table, not a leaf. */
    if (!(e & (RV_R | RV_W | RV_X)))
        p = append_str(out, p, cap, " (table)");
}

#endif

static void print_step(char *buf, int *offset, const char *level_name,
                       unsigned long long table_base, unsigned long long idx,
                       unsigned long long entry_val, unsigned long long readback,
                       int is_valid_entry, int huge_capable, int is_pte)
{
    unsigned long long entry_addr = table_base + (idx * 8);

    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "[%s]\n", level_name);
    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Table Base  : 0x%llx\n", table_base);
    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Index       : 0x%llx (%llu)\n", idx, idx);
    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Calculation : 0x%llx + (0x%llx * 8) = 0x%llx\n", table_base, idx, entry_addr);
    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Entry Value : 0x%llx\n", entry_val);

    if (table_base) {
        if (readback == entry_val) {
            *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
                "  Verify      : *(0x%llx) == 0x%llx  [kernel read-back OK]\n",
                entry_addr, entry_val);
        } else {
            *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
                "  Verify      : *(0x%llx) read 0x%llx != entry 0x%llx  [MISMATCH]\n",
                entry_addr, readback, entry_val);
        }
    }

    if (is_valid_entry) {
        char flags[96];

        decode_pte_flags(flags, sizeof(flags), entry_val, huge_capable, is_pte);
        *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
            "  Flags       : %s\n", flags);
    }

    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Status      : %s\n\n", is_valid_entry ? "Valid (Present)" : "Not Present / Empty");
}

/* One address field: its bit range, short name, value and width in bits. */
struct addr_field {
    char bits[24];
    const char *name;
    unsigned long long val;
    int nbits;
};

/* One walked level: name + the values the kernel reported for it. */
struct level_info {
    const char *name;
    const char *long_name;
    unsigned long long idx;
    unsigned long long base_phys;
    unsigned long long val;
    unsigned long long readback;
    int huge_capable;
    int is_pte;
};

/*
 * Select the active levels for this paging depth. PGD/PMD/PTE are always
 * present; PUD appears at >= 4 levels, P4D only at 5. Returns the count and
 * fills levels[] top-to-bottom.
 */
static int select_levels(const struct pagewalker_result *res, struct level_info *levels)
{
    const struct level_info all[5] = {
        { "PGD", "Page Global Directory", res->pgd_idx, res->pgd_base_phys,
          res->pgd_val, res->pgd_readback, 0, 0 },
        { "P4D", "Page 4 Directory",      res->p4d_idx, res->p4d_base_phys,
          res->p4d_val, res->p4d_readback, 0, 0 },
        { "PUD", "Page Upper Directory",  res->pud_idx, res->pud_base_phys,
          res->pud_val, res->pud_readback, 1, 0 },
        { "PMD", "Page Middle Directory", res->pmd_idx, res->pmd_base_phys,
          res->pmd_val, res->pmd_readback, 1, 0 },
        { "PTE", "Page Table Entry",      res->pte_idx, res->pte_base_phys,
          res->pte_val, res->pte_readback, 0, 1 },
    };
    int use[5] = { 1, res->paging_level >= PAGING_LEVEL_5,
                   res->paging_level >= PAGING_LEVEL_4, 1, 1 };
    int n = 0;
    int i;

    for (i = 0; i < 5; ++i)
        if (use[i])
            levels[n++] = all[i];
    return n;
}

/* Center `s` within `width` columns; any odd surplus leans to the right. */
static const char *center(char *out, size_t outsz, int width, const char *s)
{
    int len = (int)strlen(s);
    int left;
    int right;

    if (len >= width || (size_t)width + 1 > outsz) {
        snprintf(out, outsz, "%.*s", width, s);
        return out;
    }

    left = (width - len) / 2;
    right = width - len - left;

    memset(out, ' ', (size_t)left);
    memcpy(out + left, s, (size_t)len);
    memset(out + left + len, ' ', (size_t)right);
    out[width] = '\0';
    return out;
}

/* Fill `out` with `n` copies of `c`, NUL-terminated. */
static const char *fill(char *out, int n, char c)
{
    int i;

    for (i = 0; i < n; ++i) {
        out[i] = c;
    }

    out[i] = '\0';
    return out;
}

/* Write the low `nbits` of `val` as '0'/'1' characters, MSB first. */
static void bits_to_str(char *out, unsigned long long val, int nbits)
{
    int i;

    for (i = 0; i < nbits; ++i) {
        out[i] = ((val >> (nbits - 1 - i)) & 1ULL) ? '1' : '0';
    }

    out[nbits] = '\0';
}

/* Emit a "+---+---+" rule sized to the label column and `colw[]`. */
static int emit_sep(char *buf, int off, int labelw, const int *colw, int ncols)
{
    char dash[64];
    int i;

    off += snprintf(buf + off, BUFFER_SIZE - off, "+%s+", fill(dash, labelw, '-'));
    for (i = 0; i < ncols; ++i) {
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s+", fill(dash, colw[i], '-'));
    }

    off += snprintf(buf + off, BUFFER_SIZE - off, "\n");
    return off;
}

/* Emit one "| label | cell | cell |" row with every cell centered. */
static int emit_row(char *buf, int off, const char *label, int labelw,
                    const char **cells, const int *colw, int ncols)
{
    char tmp[64];
    int i;

    off += snprintf(buf + off, BUFFER_SIZE - off, "|%s|",
                    center(tmp, sizeof(tmp), labelw, label));
    for (i = 0; i < ncols; ++i) {
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s|",
                        center(tmp, sizeof(tmp), colw[i], cells[i]));
    }
    off += snprintf(buf + off, BUFFER_SIZE - off, "\n");
    return off;
}

/* Format a byte count as an exact binary-unit string (e.g. "2 MiB", "64 KiB"). */
static void human_size(char *out, size_t cap, unsigned long long bytes)
{
    static const char *unit[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    unsigned long long v = bytes;
    int u = 0;

    while (u < 4 && v >= 1024 && (v % 1024) == 0) {
        v /= 1024;
        ++u;
    }
    snprintf(out, cap, "%llu %s", v, unit[u]);
}

/* Short name of the page-table level that held the final leaf entry. */
static const char *leaf_level_name(unsigned int lvl)
{
    switch (lvl) {
    case PW_LEAF_PTE: return "PTE";
    case PW_LEAF_PMD: return "PMD";
    case PW_LEAF_PUD: return "PUD";
    case PW_LEAF_P4D: return "P4D";
    default:          return "?";
    }
}

/* Render the full walk report into `buf`; the definition lives below main(). */
static int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid,
                        int kernel_mode);

#ifndef PW_SELFTEST

/* Output rendering for the byte dump, selected on the command line. */
enum out_fmt { FMT_HEX, FMT_RAW, FMT_CJK };

/* Human string for a PW_STOP_* early-termination code. */
static const char *stop_reason(unsigned int code)
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
static int parse_size(const char *s, unsigned long long *out)
{
    unsigned long long v;
    unsigned long long mult = 1;
    char *end;
    int base = 10;

    if (!s || !*s || *s == '-' || *s == '+' || isspace((unsigned char)*s))
        return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    } else if (s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
        base = 2;
        s += 2;
    }
    if (!*s)
        return -1;

    errno = 0;
    v = strtoull(s, &end, base);
    if (errno != 0 || end == s)
        return -1;

    if (*end) {
        switch (toupper((unsigned char)*end)) {
        case 'K': mult = 1ULL << 10; break;
        case 'M': mult = 1ULL << 20; break;
        case 'G': mult = 1ULL << 30; break;
        default:  return -1;
        }
        ++end;
        if (*end == 'i' || *end == 'I')                 /* KiB style */
            ++end;
        if (*end == 'b' || *end == 'B')
            ++end;
        if (*end != '\0')
            return -1;
    }
    if (v > ULLONG_MAX / mult)                          /* overflow */
        return -1;

    *out = v * mult;
    return 0;
}

/*
 * Parse a virtual address: hex (with or without a 0x prefix), as the tool has
 * always taken it. A leading sign or empty string is rejected so "-1" is not
 * silently wrapped to ULLONG_MAX.
 */
static int parse_vaddr(const char *s, unsigned long long *out)
{
    unsigned long long v;
    char *end;

    if (!s || !*s || *s == '-' || *s == '+' || isspace((unsigned char)*s))
        return -1;
    errno = 0;
    v = strtoull(s, &end, BASE_HEX);
    if (errno != 0 || *end != '\0' || end == s)
        return -1;
    *out = v;
    return 0;
}

/*
 * Resolve a kernel address for -k. A 0x-prefixed argument is a raw address; any
 * other argument is a symbol name looked up in /proc/kallsyms (the only place a
 * module-less userspace can learn KASLR-relocated addresses). Returns 0 on
 * success, or: 1 = not found, 2 = resolved to 0 (kptr_restrict hides it from a
 * non-privileged reader), 3 = /proc/kallsyms unreadable, 4 = malformed 0x addr.
 */
static int resolve_ksym(const char *arg, unsigned long long *out)
{
    char line[512];
    char name[256];
    char type;
    unsigned long long addr;
    FILE *f;
    int found = 0;

    if (arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X'))
        return parse_vaddr(arg, out) == 0 ? 0 : 4;

    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return 3;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
            continue;
        if (strcmp(name, arg) == 0) {
            found = 1;
            *out = addr;
            break;
        }
    }
    fclose(f);

    if (!found)
        return 1;
    if (addr == 0)
        return 2;
    return 0;
}

/*
 * Look one symbol up in an ELF64 object file. On success sets *st_value (the
 * symbol's link-time address) and *load_vaddr (the p_vaddr of the PT_LOAD that
 * covers file offset 0, i.e. the object's link base) and returns 1. Searches
 * .symtab first, then .dynsym. Every offset is bounds-checked against the mapped
 * size so a truncated or malformed file cannot walk off the end. Returns 0 if
 * the symbol is absent or the file is not a usable ELF64 object.
 */
static int elf_lookup(const char *path, const char *name,
                      unsigned long long *st_value, unsigned long long *load_vaddr)
{
    int fd = open(path, O_RDONLY);
    struct stat stb;
    const unsigned char *base;
    const Elf64_Ehdr *eh;
    size_t sz;
    int found = 0;
    unsigned i;

    if (fd < 0)
        return 0;
    if (fstat(fd, &stb) != 0 || (size_t)stb.st_size < sizeof(*eh)) {
        close(fd);
        return 0;
    }
    sz = (size_t)stb.st_size;
    base = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED)
        return 0;

    eh = (const Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64)
        goto done;

    /* Link base = p_vaddr of the PT_LOAD covering file offset 0. */
    *load_vaddr = 0;
    if (eh->e_phoff && eh->e_phnum &&
        eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) <= sz) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(base + eh->e_phoff);

        for (i = 0; i < eh->e_phnum; ++i) {
            if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0) {
                *load_vaddr = ph[i].p_vaddr;
                break;
            }
        }
    }

    if (!eh->e_shoff || !eh->e_shnum ||
        eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > sz)
        goto done;

    {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
        int pass;

        /* Pass 0: SHT_SYMTAB (full table); pass 1: SHT_DYNSYM (fallback). */
        for (pass = 0; pass < 2 && !found; ++pass) {
            unsigned want = pass == 0 ? SHT_SYMTAB : SHT_DYNSYM;

            for (i = 0; i < eh->e_shnum && !found; ++i) {
                const Elf64_Sym *sym;
                const char *str;
                size_t nsym, strsz, j;
                unsigned link = sh[i].sh_link;

                if (sh[i].sh_type != want || sh[i].sh_entsize == 0)
                    continue;
                if (link >= eh->e_shnum)
                    continue;
                if (sh[i].sh_offset + sh[i].sh_size > sz ||
                    sh[link].sh_offset + sh[link].sh_size > sz)
                    continue;

                sym = (const Elf64_Sym *)(base + sh[i].sh_offset);
                str = (const char *)(base + sh[link].sh_offset);
                strsz = sh[link].sh_size;
                nsym = sh[i].sh_size / sizeof(Elf64_Sym);

                for (j = 0; j < nsym; ++j) {
                    unsigned nameoff = sym[j].st_name;

                    if (nameoff >= strsz || sym[j].st_shndx == SHN_UNDEF)
                        continue;
                    if (strcmp(str + nameoff, name) == 0) {
                        *st_value = sym[j].st_value;
                        found = 1;
                        break;
                    }
                }
            }
        }
    }

done:
    munmap((void *)base, sz);
    return found;
}

/*
 * Resolve a symbol name to a runtime address inside process `pid`. This is done
 * entirely in userspace, as it should be: the kernel primitive only reads a
 * (pid, address) pair. We read /proc/pid/maps for each file-backed object's load
 * base (the mapping at file offset 0) and add the symbol's link-time value minus
 * the object's link base. It resolves functions and global/static data in the
 * executable and its shared libraries; a local, stack or heap variable has no
 * symbol and cannot be resolved. Returns 0 on success, or fills errbuf and
 * returns non-zero (1 = not resolvable, 2 = /proc/pid/maps unreadable).
 */
static int resolve_user_sym(unsigned int pid, const char *name,
                            unsigned long long *out, char *errbuf, size_t errcap)
{
    char mpath[64];
    char line[4096];
    char seen[64][512];
    int nseen = 0;
    FILE *f;
    int i;

    snprintf(mpath, sizeof(mpath), "/proc/%u/maps", pid);
    f = fopen(mpath, "r");
    if (!f) {
        snprintf(errbuf, errcap, "cannot read %s (process gone, or not permitted)", mpath);
        return 2;
    }

    /*
     * Collect the offset-0 mapping (the load base) of each distinct file-backed
     * object. That mapping's start minus the object's link base is the load bias.
     */
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off;
        char perms[8];
        char path[512];
        unsigned long long st_value, load_vaddr;

        path[0] = '\0';
        if (sscanf(line, "%llx-%llx %7s %llx %*x:%*x %*u %511[^\n]",
                   &start, &end, perms, &off, path) < 5)
            continue;
        if (off != 0 || path[0] != '/')
            continue;

        /* Skip a path already tried (an object has one offset-0 mapping anyway). */
        for (i = 0; i < nseen; ++i)
            if (strcmp(seen[i], path) == 0)
                break;
        if (i < nseen)
            continue;
        if (nseen < (int)(sizeof(seen) / sizeof(seen[0])))
            snprintf(seen[nseen++], sizeof(seen[0]), "%s", path);

        if (elf_lookup(path, name, &st_value, &load_vaddr)) {
            *out = st_value + start - load_vaddr;
            fclose(f);
            return 0;
        }
    }
    fclose(f);

    snprintf(errbuf, errcap,
             "symbol '%s' not found in PID %u's objects; a local/stack/heap "
             "variable has no symbol - pass its runtime address (e.g. printed "
             "with %%p)", name, pid);
    return 1;
}

/*
 * Decode one UTF-8 scalar at p (with `avail` bytes left). Returns 1 and sets
 * *cp / *len for a well-formed, complete, non-overlong, non-surrogate scalar;
 * otherwise returns 0 with *len = 1 (a truncated sequence at the end of the
 * buffer, a stray continuation byte, or an invalid encoding).
 */
static int utf8_decode(const unsigned char *p, size_t avail, uint32_t *cp, int *len)
{
    unsigned char c;
    uint32_t v;
    uint32_t min;
    int n;
    int i;

    if (avail == 0) {
        *len = 1;
        return 0;
    }
    c = p[0];
    if (c < 0x80) {
        *cp = c;
        *len = 1;
        return 1;
    }
    if ((c & 0xe0) == 0xc0) {
        n = 2;
        v = c & 0x1f;
        min = 0x80;
    } else if ((c & 0xf0) == 0xe0) {
        n = 3;
        v = c & 0x0f;
        min = 0x800;
    } else if ((c & 0xf8) == 0xf0) {
        n = 4;
        v = c & 0x07;
        min = 0x10000;
    } else {
        *len = 1;
        return 0;
    }
    if ((size_t)n > avail) {
        *len = 1;
        return 0;
    }
    for (i = 1; i < n; ++i) {
        if ((p[i] & 0xc0) != 0x80) {
            *len = 1;
            return 0;
        }
        v = (v << 6) | (p[i] & 0x3f);
    }
    if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) {
        *len = 1;
        return 0;
    }
    *cp = v;
    *len = n;
    return 1;
}

/*
 * A scalar that must never be echoed to the gutter: it either does nothing
 * visible or can hijack the terminal (C0/C1 controls, DEL, line/paragraph
 * separators, zero-width and directional-format characters, the BOM). Such a
 * scalar is shown as '.' instead.
 */
static int cp_is_unsafe(uint32_t cp)
{
    if (cp < 0x20 || cp == 0x7f)              /* C0 controls + DEL */
        return 1;
    if (cp >= 0x80 && cp <= 0x9f)             /* C1 controls */
        return 1;
    if (cp == 0x2028 || cp == 0x2029)         /* line / paragraph separators */
        return 1;
    if (cp >= 0x200b && cp <= 0x200f)         /* zero-width + LRM/RLM */
        return 1;
    if (cp >= 0x202a && cp <= 0x202e)         /* bidi embeddings / overrides */
        return 1;
    if (cp >= 0x2066 && cp <= 0x2069)         /* bidi isolates */
        return 1;
    if (cp == 0xfeff)                         /* BOM / ZWNBSP */
        return 1;
    if (cp >= 0xfff9 && cp <= 0xfffb)         /* interlinear annotation */
        return 1;
    return 0;
}

/*
 * Terminal display width of a scalar (0, 1 or 2 columns), after Markus Kuhn's
 * public-domain wcwidth: combining marks are zero-width, East-Asian Wide and
 * Fullwidth characters (CJK ideographs, Hangul syllables, kana, ...) are two
 * columns, everything else one. Locale-independent, so it works in a bare
 * static initramfs where setlocale() has no data. Returns -1 for a control.
 */
static int mk_wcwidth(uint32_t ucs)
{
    static const struct { uint32_t first, last; } combining[] = {
        { 0x0300, 0x036f }, { 0x0483, 0x0489 }, { 0x0591, 0x05bd },
        { 0x05bf, 0x05bf }, { 0x05c1, 0x05c2 }, { 0x05c4, 0x05c5 },
        { 0x05c7, 0x05c7 }, { 0x0610, 0x061a }, { 0x064b, 0x065f },
        { 0x0670, 0x0670 }, { 0x06d6, 0x06dc }, { 0x06df, 0x06e4 },
        { 0x06e7, 0x06e8 }, { 0x06ea, 0x06ed }, { 0x0711, 0x0711 },
        { 0x0730, 0x074a }, { 0x07a6, 0x07b0 }, { 0x07eb, 0x07f3 },
        { 0x0901, 0x0902 }, { 0x093c, 0x093c }, { 0x0941, 0x0948 },
        { 0x094d, 0x094d }, { 0x0951, 0x0954 }, { 0x0962, 0x0963 },
        { 0x0e31, 0x0e31 }, { 0x0e34, 0x0e3a }, { 0x0e47, 0x0e4e },
        { 0x1dc0, 0x1dff }, { 0x20d0, 0x20f0 }, { 0xfe20, 0xfe23 },
    };
    int lo = 0;
    int hi = (int)(sizeof(combining) / sizeof(combining[0])) - 1;

    if (ucs == 0)
        return 0;
    if (ucs < 32 || (ucs >= 0x7f && ucs < 0xa0))
        return -1;

    while (lo <= hi) {                        /* zero-width combining marks */
        int mid = (lo + hi) / 2;

        if (ucs < combining[mid].first)
            hi = mid - 1;
        else if (ucs > combining[mid].last)
            lo = mid + 1;
        else
            return 0;
    }

    return 1 +
        (ucs >= 0x1100 &&
         (ucs <= 0x115f ||                                   /* Hangul Jamo */
          ucs == 0x2329 || ucs == 0x232a ||
          (ucs >= 0x2e80 && ucs <= 0xa4cf && ucs != 0x303f) || /* CJK .. Yi */
          (ucs >= 0xac00 && ucs <= 0xd7a3) ||                /* Hangul Syllables */
          (ucs >= 0xf900 && ucs <= 0xfaff) ||                /* CJK Compat */
          (ucs >= 0xfe10 && ucs <= 0xfe19) ||                /* Vertical forms */
          (ucs >= 0xfe30 && ucs <= 0xfe6f) ||                /* CJK Compat Forms */
          (ucs >= 0xff00 && ucs <= 0xff60) ||                /* Fullwidth Forms */
          (ucs >= 0xffe0 && ucs <= 0xffe6) ||
          (ucs >= 0x20000 && ucs <= 0x2fffd) ||
          (ucs >= 0x30000 && ucs <= 0x3fffd)));
}

/*
 * Render bytes in the hexdump -C shape: an 8-hex offset column relative to the
 * start address (the absolute VA/PA are printed once in the banner above, so the
 * rows stay pipe- and xxd-comparable), 16 bytes split 8 + 8, then a text gutter
 * of a fixed 16 display columns. In ASCII mode each printable byte prints itself
 * and the rest print '.'. In CJK mode the gutter decodes UTF-8 across the whole
 * buffer (so a multi-byte character straddling a 16-byte line still shows), each
 * printable scalar occupies its true display width, unsafe scalars collapse to
 * '.', and every line is padded to the same 16 columns so the borders align.
 */
static void dump_bytes(FILE *out, const unsigned char *b, size_t n, int cjk,
                       int cols, int group, int upper)
{
    const char *offfmt = upper ? "%08llX  " : "%08llx  ";
    const char *hexfmt = upper ? "%02X " : "%02x ";
    size_t off;
    size_t skip = 0;      /* CJK: leading bytes already consumed by a prior glyph */

    for (off = 0; off < n; off += (size_t)cols) {
        size_t linelen = (n - off < (size_t)cols) ? (n - off) : (size_t)cols;
        int k;

        fprintf(out, offfmt, (unsigned long long)off);
        for (k = 0; k < cols; ++k) {
            if ((size_t)k < linelen)
                fprintf(out, hexfmt, b[off + k]);
            else
                fputs("   ", out);
            if (group > 0 && (k + 1) % group == 0 && k + 1 < cols)
                fputc(' ', out);
        }
        fputc('|', out);

        if (!cjk) {
            for (k = 0; (size_t)k < linelen; ++k) {
                unsigned char c = b[off + k];

                fputc((c >= 0x20 && c <= 0x7e) ? (int)c : '.', out);
            }
            for (k = (int)linelen; k < cols; ++k)
                fputc(' ', out);
        } else {
            size_t pos = off + (skip < linelen ? skip : linelen);
            size_t next_skip = 0;
            int col = 0;

            skip = 0;
            while (pos < off + linelen && col < cols) {
                uint32_t cp;
                int len;
                int w;

                if (!utf8_decode(b + pos, n - pos, &cp, &len)) {
                    fputc('.', out);
                    ++col;
                    pos += 1;
                    continue;
                }
                w = mk_wcwidth(cp);
                if (cp_is_unsafe(cp) || w <= 0 || col + w > cols) {
                    fputc('.', out);
                    ++col;
                } else {
                    fwrite(b + pos, 1, (size_t)len, out);
                    col += w;
                }
                pos += len;
                if (pos > off + linelen)
                    next_skip = pos - (off + linelen);
            }
            for (; col < cols; ++col)
                fputc(' ', out);
            skip = next_skip;
        }

        fputs("|\n", out);
    }
}

/*
 * Drive command 2 to copy `size` bytes starting at `start` into `buf`, looping
 * over the kernel's PW_READ_MAX per-call ceiling. The walk of the very first
 * address is captured in *out_info for the report. A short return (a hole or an
 * unmapped page) stops the loop and reports how far it got via *out_stopped.
 * Returns 0, or a negative errno from the ioctl.
 */
static int do_read(int fd, int kernel, int allow_mmio, unsigned int pid,
                   unsigned long long start, unsigned long long size, unsigned char *buf,
                   unsigned long long *out_got, unsigned int *out_stopped,
                   struct pagewalker_result *out_info)
{
    unsigned long long done = 0;
    int have_info = 0;

    do {
        struct pagewalker_read_request rr;
        unsigned long long chunk = size - done;

        if (chunk > PW_READ_MAX)
            chunk = PW_READ_MAX;

        memset(&rr, 0, sizeof(rr));
        rr.pid = pid;
        rr.flags = (kernel ? PW_READ_F_KERNEL : 0) |
                   (allow_mmio ? PW_READ_F_ALLOW_MMIO : 0);
        rr.vaddr = start + done;
        rr.size = chunk;
        rr.ubuf = (unsigned long long)(uintptr_t)(buf + done);

        if (ioctl(fd, PAGEWALKER_IOC_READ, &rr) < 0)
            return -errno;

        if (!have_info) {
            *out_info = rr.info;
            have_info = 1;
        }
        done += rr.bytes_read;
        *out_stopped = rr.stopped;

        if (rr.bytes_read < chunk)            /* truncated by a hole / unmapped */
            break;
    } while (done < size);

    *out_got = done;
    return 0;
}

int main(int argc, char *argv[])
{
    int fd = -1;
    int ret_code = EXIT_FAILURE;
    int kernel = 0;
    int force_tty = 0;
    int have_size = 0;
    int allow_mmio = 0;
    int no_report = 0;
    int cols = 16;
    int group = 8;
    int upper = 0;
    enum out_fmt fmt = FMT_HEX;
    unsigned int pid = 0;
    unsigned long long start = 0;
    unsigned long long size = 0;
    int npos;
    int opt;

    enum { OPT_ALLOW_MMIO = 1000, OPT_NO_REPORT };
    static struct option long_options[] = {
        {"help",       no_argument,       0, 'h'},
        {"kernel",     no_argument,       0, 'k'},
        {"raw",        no_argument,       0, 'r'},
        {"hex",        no_argument,       0, 'x'},
        {"cjk",        no_argument,       0, 'c'},
        {"force",      no_argument,       0, 'F'},
        {"upper",      no_argument,       0, 'u'},
        {"format",     required_argument, 0, 'f'},
        {"cols",       required_argument, 0, 'w'},
        {"group",      required_argument, 0, 'g'},
        {"allow-mmio", no_argument,       0, OPT_ALLOW_MMIO},
        {"no-report",  no_argument,       0, OPT_NO_REPORT},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hkrxcFuf:w:g:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'k': kernel = 1; break;
        case 'r': fmt = FMT_RAW; break;
        case 'x': fmt = FMT_HEX; break;
        case 'c': fmt = FMT_CJK; break;
        case 'F': force_tty = 1; break;
        case 'u': upper = 1; break;
        case OPT_ALLOW_MMIO: allow_mmio = 1; break;
        case OPT_NO_REPORT: no_report = 1; break;
        case 'w': {
            char *e;
            long v = strtol(optarg, &e, 10);

            if (*e != '\0' || v < 1 || v > 256) {
                fprintf(stderr, "Error: --cols must be 1..256.\n");
                return EXIT_FAILURE;
            }
            cols = (int)v;
            break;
        }
        case 'g': {
            char *e;
            long v = strtol(optarg, &e, 10);

            if (*e != '\0' || v < 0 || v > 256) {
                fprintf(stderr, "Error: --group must be 0..256 (0 = no grouping).\n");
                return EXIT_FAILURE;
            }
            group = (int)v;
            break;
        }
        case 'f':
            if (!strcmp(optarg, "hex"))
                fmt = FMT_HEX;
            else if (!strcmp(optarg, "raw"))
                fmt = FMT_RAW;
            else if (!strcmp(optarg, "cjk") || !strcmp(optarg, "utf8"))
                fmt = FMT_CJK;
            else {
                fprintf(stderr, "Error: unknown format '%s' (hex|raw|cjk).\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    npos = argc - optind;

    if (kernel) {
        int r;

        if (npos < 1 || npos > 2) {
            fprintf(stderr, "Error: expected <symbol|0xaddr> [size].\n");
            return EXIT_FAILURE;
        }
        r = resolve_ksym(argv[optind], &start);
        if (r == 1) {
            fprintf(stderr, "Error: symbol '%s' not found in /proc/kallsyms.\n", argv[optind]);
            return EXIT_FAILURE;
        }
        if (r == 2) {
            fprintf(stderr, "Error: '%s' resolves to 0 (kptr_restrict hides it; run as root).\n",
                    argv[optind]);
            return EXIT_FAILURE;
        }
        if (r == 3) {
            fprintf(stderr, "Error: cannot read /proc/kallsyms.\n");
            return EXIT_FAILURE;
        }
        if (r == 4) {
            fprintf(stderr, "Error: invalid kernel address '%s'.\n", argv[optind]);
            return EXIT_FAILURE;
        }
        if (npos == 2) {
            if (parse_size(argv[optind + 1], &size) != 0) {
                fprintf(stderr, "Error: invalid size '%s'.\n", argv[optind + 1]);
                return EXIT_FAILURE;
            }
            have_size = 1;
        }
    } else {
        char *endptr;
        long pid_long;

        if (npos < 2 || npos > 3) {
            fprintf(stderr, npos < 2 ? "Error: too few arguments.\n"
                                     : "Error: too many arguments.\n");
            return EXIT_FAILURE;
        }
        errno = 0;
        pid_long = strtol(argv[optind], &endptr, BASE_DECIMAL);
        if (errno != 0 || *endptr != '\0' || argv[optind][0] == '\0' || pid_long <= 0) {
            fprintf(stderr, "Error: Invalid PID.\n");
            return EXIT_FAILURE;
        }
        if ((unsigned long)pid_long > get_system_pid_max()) {
            fprintf(stderr, "Error: PID out of range.\n");
            return EXIT_FAILURE;
        }
        pid = (unsigned int)pid_long;

        /*
         * The target is a hex address, or a symbol resolved against the process
         * itself. A 0x prefix or an all-hex-digit token is an address; anything
         * with a non-hex character is a symbol name, looked up in the process's
         * own objects. Resolution and its failure live here, in the CLI - the
         * kernel only ever sees a (pid, address) pair.
         */
        {
            const char *tgt = argv[optind + 1];
            const char *h = tgt;
            int is_hex = tgt[0] != '\0';

            if (h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
                h += 2;
            if (*h == '\0')
                is_hex = 0;
            for (; *h; ++h)
                if (!isxdigit((unsigned char)*h)) {
                    is_hex = 0;
                    break;
                }

            if (is_hex) {
                if (parse_vaddr(tgt, &start) != 0) {
                    fprintf(stderr, "Error: Invalid Address.\n");
                    return EXIT_FAILURE;
                }
            } else {
                char err[256];

                if (resolve_user_sym(pid, tgt, &start, err, sizeof(err)) != 0) {
                    fprintf(stderr, "Error: %s\n", err);
                    return EXIT_FAILURE;
                }
                fprintf(stderr, "resolved %s in PID %u -> 0x%llx\n", tgt, pid, start);
            }
        }
        if (npos == 3) {
            if (parse_size(argv[optind + 2], &size) != 0) {
                fprintf(stderr, "Error: invalid size '%s'.\n", argv[optind + 2]);
                return EXIT_FAILURE;
            }
            have_size = 1;
        }
    }

    if (size > (256ULL << 20)) {
        fprintf(stderr, "Error: size too large (max 256 MiB per invocation).\n");
        return EXIT_FAILURE;
    }

    fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        switch (errno) {
        case EACCES:
            fprintf(stderr, "Error: cannot open %s: Permission denied (try sudo).\n",
                    PAGEWALKER_PATH);
            break;
        case ENOENT:
            fprintf(stderr, "Error: %s not found (is the module loaded?).\n",
                    PAGEWALKER_PATH);
            break;
        default:
            perror("Error opening device");
            break;
        }
        goto cleanup;
    }

    /* Legacy path: a process walk with no dump uses command 1 verbatim. */
    if (!kernel && !have_size) {
        struct pagewalker_request req;
        char buf[BUFFER_SIZE];

        memset(&req, 0, sizeof(req));
        req.pid = pid;
        req.info.target_vaddr = start;

        if (ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req) < 0) {
            switch (errno) {
            case ESRCH:
                fprintf(stderr, "Error: PID %u not found.\n", req.pid);
                break;
            case EADDRNOTAVAIL:
                fprintf(stderr, "Error: 0x%llx is not a canonical address.\n", start);
                break;
            case EINVAL:
                fprintf(stderr, "Error: PID %u is out of range.\n", req.pid);
                break;
            default:
                perror("ioctl");
                break;
            }
            goto cleanup;
        }

        build_report(buf, &req.info, req.pid, 0);
        printf("%s", buf);
        ret_code = EXIT_SUCCESS;
        goto cleanup;
    }

    /* Read path (command 2): fills the walk of the start address and the bytes. */
    {
        struct pagewalker_result info;
        unsigned char *data = NULL;
        unsigned long long got = 0;
        unsigned int stopped = PW_STOP_OK;
        int r;

        memset(&info, 0, sizeof(info));
        if (size) {
            data = malloc(size);
            if (!data) {
                fprintf(stderr, "Error: out of memory for %llu bytes.\n", size);
                goto cleanup;
            }
        }

        r = do_read(fd, kernel, allow_mmio, pid, start, size, data, &got, &stopped, &info);
        if (r < 0) {
            switch (-r) {
            case ESRCH:
                fprintf(stderr, "Error: PID %u not found.\n", pid);
                break;
            case EINVAL:
                fprintf(stderr, "Error: PID %u is out of range.\n", pid);
                break;
            default:
                errno = -r;
                perror("ioctl");
                break;
            }
            free(data);
            goto cleanup;
        }

        if (fmt == FMT_RAW) {
            if (!force_tty && isatty(STDOUT_FILENO)) {
                fprintf(stderr,
                    "Error: refusing to write raw bytes to a terminal; pipe the output or pass -F.\n");
                free(data);
                goto cleanup;
            }
            if (got && fwrite(data, 1, (size_t)got, stdout) != (size_t)got) {
                perror("write");
                free(data);
                goto cleanup;
            }
            if (stopped != PW_STOP_OK)
                fprintf(stderr, "Note: stopped after %llu of %llu bytes (%s).\n",
                        got, size, stop_reason(stopped));
        } else {
            char buf[BUFFER_SIZE];

            if (!no_report) {
                build_report(buf, &info, pid, kernel);
                printf("%s", buf);
            }
            if (size) {
                char szs[32];

                human_size(szs, sizeof(szs), info.page_size);
                printf("\n=== Memory Dump: %llu of %llu byte%s ===\n",
                       got, size, size == 1 ? "" : "s");
                printf("  Start VA : 0x%016llx\n", start);
                if (info.is_valid)
                    printf("  Start PA : 0x%016llx  (%s leaf at %s%s)\n",
                           (unsigned long long)info.final_phys_addr, szs,
                           leaf_level_name(info.mapping_level),
                           info.is_contiguous ? ", contiguous" : "");
                printf("  Offsets below are relative to the start VA.\n");
                if (stopped != PW_STOP_OK)
                    printf("  (stopped: %s)\n", stop_reason(stopped));
                printf("\n");
                dump_bytes(stdout, data, (size_t)got, fmt == FMT_CJK, cols, group, upper);
            }
        }

        free(data);
        ret_code = EXIT_SUCCESS;
    }

cleanup:
    if (fd >= 0)
        close(fd);
    return ret_code;
}
#endif /* !PW_SELFTEST */

/* Render the full walk report into `buf` (BUFFER_SIZE bytes); returns length. */
static int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid,
                        int kernel_mode)
{
    int offset = 0;
    struct level_info levels[5];
    int nlev = select_levels(res, levels);
    int idx_bits = (int)res->page_shift - 3;        /* 8-byte entries per table */
    int va_bits = (int)res->va_bits;
    char rdesc[256];

    /*
     * For a standard (non-contiguous) huge mapping, the translation stops at a
     * higher level and the page offset spans that level's size, so show only
     * the levels down to the leaf and widen the offset field to log2(page_size).
     * Contiguous / NAPOT leaves keep the base-granule breakdown (their span is
     * not a clean cut at a level boundary) and are called out in words instead.
     */
    int nshow = nlev;
    int offbits = (int)res->page_shift;

    if (res->is_valid && !res->is_contiguous &&
        res->mapping_level != PW_LEAF_PTE && res->mapping_level != PW_LEAF_NONE) {
        const char *target = leaf_level_name(res->mapping_level);
        int li;

        for (li = 0; li < nlev; ++li)
            if (strcmp(levels[li].name, target) == 0)
                break;
        if (li < nlev) {
            unsigned long long s = res->page_size;

            nshow = li + 1;
            offbits = 0;
            while (s > 1) {
                s >>= 1;
                ++offbits;
            }
        }
    }

    /* --- Report Header --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "\n=========================================================\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " %s Page Table Walk Report\n", PW_ARCH_NAME);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "=========================================================\n");
    if (kernel_mode)
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            " Target       : kernel address space\n");
    else
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            " Target PID   : %u\n", pid);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target VAddr : 0x%016llx\n", res->target_vaddr);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Paging Mode  : %d-Level Paging (VA %d-bit, page %u KiB)\n",
        res->paging_level, va_bits, (1u << res->page_shift) / 1024);

    /*
     * --- Address field breakdown ---
     * Built from the kernel-reported geometry (level count, VA width, page
     * size): an Extension field, one field per walked level (each idx_bits
     * wide, the top one trimmed to fill VA), then the page offset.
     */
    struct addr_field fields[9];
    int nf = 0;
    int shift_top = res->page_shift + (nlev - 1) * idx_bits;
    int i;

    snprintf(fields[nf].bits, sizeof(fields[nf].bits), "%d-%d", 63, va_bits);
    fields[nf].name = "Extension";
    fields[nf].val = va_bits >= 64 ? 0 : (res->target_vaddr >> va_bits);
    fields[nf].nbits = 64 - va_bits;
    ++nf;

    for (i = 0; i < nshow; ++i) {
        int shift = res->page_shift + (nlev - 1 - i) * idx_bits;
        int nbits = (i == 0) ? (va_bits - shift_top) : idx_bits;

        snprintf(fields[nf].bits, sizeof(fields[nf].bits), "%d-%d",
                 shift + nbits - 1, shift);
        fields[nf].name = levels[i].name;
        fields[nf].val = levels[i].idx;
        fields[nf].nbits = nbits;
        ++nf;
    }

    snprintf(fields[nf].bits, sizeof(fields[nf].bits), "%d-%d", offbits - 1, 0);
    fields[nf].name = "offset";
    fields[nf].val = res->target_vaddr & ((1ULL << offbits) - 1);
    fields[nf].nbits = offbits;
    ++nf;

    char hexs[9][16];
    char raws[9][48];

    for (i = 0; i < nf; ++i) {
        snprintf(hexs[i], sizeof(hexs[i]), "0x%0*llx", (fields[i].nbits + 3) / 4, fields[i].val);
        bits_to_str(raws[i], fields[i].val, fields[i].nbits);
    }

    /*
     * Index box: one column per field. Each column's width is the widest cell
     * in it (bits / name / hex / binary); every cell is centered to that width,
     * so the rows stay aligned even though their content sizes differ.
     */
    int colw[9];
    const char *bitscells[9];
    const char *namecells[9];
    const char *hexcells[9];
    const char *bincells[9];
    int labelw = (int)strlen("Bits") + 2;

    for (i = 0; i < nf; ++i) {
        int w = (int)strlen(fields[i].bits);

        if ((int)strlen(fields[i].name) > w)
            w = (int)strlen(fields[i].name);
        if ((int)strlen(hexs[i]) > w)
            w = (int)strlen(hexs[i]);
        if ((int)strlen(raws[i]) > w)
            w = (int)strlen(raws[i]);

        colw[i] = w + 2;
        bitscells[i] = fields[i].bits;
        namecells[i] = fields[i].name;
        hexcells[i] = hexs[i];
        bincells[i] = raws[i];
    }

    offset = emit_sep(buf, offset, labelw, colw, nf);
    offset = emit_row(buf, offset, "Bits", labelw, bitscells, colw, nf);
    offset = emit_sep(buf, offset, labelw, colw, nf);
    offset = emit_row(buf, offset, "IDX", labelw, namecells, colw, nf);
    offset = emit_row(buf, offset, "VAL", labelw, hexcells, colw, nf);
    offset = emit_row(buf, offset, "BIN", labelw, bincells, colw, nf);
    offset = emit_sep(buf, offset, labelw, colw, nf);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "\n");

    /*
     * Full 64-bit address, split on the page-table field boundaries. Each binary
     * group is placed at the exact column its BIN cell occupies in the table, so
     * the two rows line up even when a column's widest cell is its name rather
     * than its binary.
     */
    int binstart[9];
    int acc = 1 + labelw + 1;   /* column where the first cell's content begins */

    for (i = 0; i < nf; ++i) {
        int leftpad = (colw[i] - (int)strlen(raws[i])) / 2;

        binstart[i] = acc + leftpad;
        acc += colw[i] + 1;
    }

    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target VAddr (64-bit, MSB -> LSB): 0x%016llx\n", res->target_vaddr);

    char sp[96];
    int cur = binstart[0] - 3;   /* leave room for "-> " just before the first group */

    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "%s-> ", fill(sp, cur, ' '));
    cur += 3;
    for (i = 0; i < nf; ++i) {
        if (binstart[i] > cur) {
            offset += snprintf(buf + offset, BUFFER_SIZE - offset, "%s",
                               fill(sp, binstart[i] - cur, ' '));
            cur = binstart[i];
        }
        offset += snprintf(buf + offset, BUFFER_SIZE - offset, "%s", raws[i]);
        cur += (int)strlen(raws[i]);
    }
    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "\n\n");

    /* --- Detailed Steps --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "=== Translation Steps ===\n\n");

    /* Step 0: the arch root translation register. */
    describe_root_reg(rdesc, sizeof(rdesc), res, kernel_mode);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "[Step 0: %s Register]\n", root_reg_name(kernel_mode));
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "  Physical Addr : 0x%llx\n", res->root_table_phys);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "  Description   : %s\n\n", rdesc);

    /* Steps 1..N: one per walked level (down to the leaf for a huge page). */
    for (i = 0; i < nshow; ++i) {
        char step_name[64];

        snprintf(step_name, sizeof(step_name), "Step %d: %s (%s)",
                 i + 1, levels[i].name, levels[i].long_name);
        print_step(buf, &offset, step_name,
                   levels[i].base_phys, levels[i].idx, levels[i].val,
                   levels[i].readback, (int)(levels[i].val & 1),
                   levels[i].huge_capable, levels[i].is_pte);
    }

    /* --- Final Verification --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "--------------------------------------------------------\n");

    if (res->is_valid) {
        char szs[32];

        human_size(szs, sizeof(szs), res->page_size);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[FINAL RESULT]\n");
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Mapped Page    : %s  (leaf at %s%s%s)\n", szs,
            leaf_level_name(res->mapping_level),
            res->is_contiguous ? ", " : "",
            res->is_contiguous ? PW_CONT_TERM : "");
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Page Base Phys : 0x%llx\n", res->page_base_phys);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Offset         : 0x%llx\n", res->page_offset);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Final Phys Addr: 0x%llx\n\n", res->final_phys_addr);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[VERIFICATION]\n");
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Content at Phys: 0x%016llx  (u64, little-endian; bytes appear reversed in a dump)\n",
            res->value_at_phys);
    } else {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[FINAL RESULT]\n  Translation Stopped (Page Fault / Not Mapped / Swapped Out)\n");
    }
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "--------------------------------------------------------\n");

    return offset;
}

#ifdef PW_SELFTEST
/*
 * Self-contained verifier for QEMU. Built with -DPW_SELFTEST -static. When run
 * as PID 1 it acts as init (mount the pseudo-filesystems, load /pagewalker.ko),
 * then in every case it walks one of its OWN mappings and checks that the
 * physical content the module read back equals the sentinel it wrote. This
 * exercises the exact ABI + report path the CLI uses, on whatever arch it runs.
 */
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>

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

    if (fd < 0)
        return -1;
    r = syscall(SYS_finit_module, fd, "", 0);
    close(fd);
    return (int)r;
}

/* One self-test case: map a region (optionally hugetlb), probe an offset. */
struct pw_case {
    const char *name;
    size_t map_size;
    int huge_shift;                 /* 0 = base page; else log2(huge size) */
    size_t probe_off;               /* 8-aligned offset to write + walk */
    unsigned long long exp_size;    /* expected page_size (0 = don't check) */
    unsigned int exp_level;         /* expected mapping_level (0 = don't check) */
    int exp_contig;                 /* expected is_contiguous (-1 = don't check) */
};

/* Best-effort hugetlb pool reservation; a size the arch can't back just fails. */
static void reserve_pool(unsigned long kib, const char *count)
{
    char path[128];
    int fd;

    snprintf(path, sizeof(path),
             "/sys/kernel/mm/hugepages/hugepages-%lukB/nr_hugepages", kib);
    fd = open(path, O_WRONLY);
    if (fd < 0)
        return;
    if (write(fd, count, strlen(count)) < 0)
        ; /* ignore: the case mmap will SKIP if the pool stays empty */
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

    if (c->huge_shift)
        flags |= MAP_HUGETLB | (c->huge_shift << MAP_HUGE_SHIFT);

    base = mmap(NULL, c->map_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (base == MAP_FAILED) {
        printf("CASE %-4s: SKIP  (mmap len=%zu huge_shift=%d errno=%d - pool unavailable)\n",
               c->name, c->map_size, c->huge_shift, errno);
        return 2;
    }

    probe = (volatile unsigned long long *)((char *)base + c->probe_off);
    *probe = sentinel;   /* fault in + write the sentinel at the probed offset */

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

    if (!req.info.is_valid)
        bad = 1;
    if (req.info.value_at_phys != sentinel)
        bad = 1;        /* the probed offset's physical address must be correct */
    if (c->exp_size && req.info.page_size != c->exp_size)
        bad = 1;
    if (c->exp_level && req.info.mapping_level != c->exp_level)
        bad = 1;
    if (c->exp_contig >= 0 && (int)req.info.is_contiguous != c->exp_contig)
        bad = 1;

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
        { "4K",  ps,            0,    0,           (unsigned long long)ps, PW_LEAF_PTE, 0  },
        { "64K", (size_t)1<<16, 16,   0x9000,      1ULL<<16,               PW_LEAF_PTE, 1  },
        { "2M",  (size_t)1<<21, 21,   0x150000,    1ULL<<21,               PW_LEAF_PMD, 0  },
        { "1G",  (size_t)1<<30, 30,   0x20000000,  1ULL<<30,               PW_LEAF_PUD, 0  },
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
                if (cfd > 2)
                    close(cfd);
            }
        }
        if (load_module("/pagewalker.ko") != 0)
            printf("SELFTEST: finit_module(/pagewalker.ko) failed errno=%d\n", errno);
        else
            printf("SELFTEST: module loaded\n");
    }

    /* 64K = arm64 cont-PTE / riscv NAPOT; 2M = PMD; 1G = PUD (boot-reserved). */
    reserve_pool(64, "16");
    reserve_pool(2048, "16");
    reserve_pool(1048576, "1");

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int r = run_case(&cases[i], 0xCAFEBABEDEADBEEFULL + i);

        if (r == 0)
            ++passed;
        else if (r == 1)
            ++failed;
        else
            ++skipped;
    }

    printf("\nSELFTEST SUMMARY (%s): passed=%d failed=%d skipped=%d\n",
           PW_ARCH_NAME, passed, failed, skipped);
    /* Require the always-available cases (4K + 2M) and zero failures. */
    if (failed == 0 && passed >= 2)
        printf("SELFTEST: ALL PASS (%s)\n", PW_ARCH_NAME);
    else
        printf("SELFTEST: FAIL (%s)\n", PW_ARCH_NAME);

    fflush(stdout);
    if (is_init) {
        sync();
        reboot(RB_POWER_OFF);
    }
    return (failed == 0 && passed >= 2) ? 0 : 1;
}
#endif /* PW_SELFTEST */
