#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "report.h"

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
    if (kernel) {
        snprintf(out, cap,
                 "TTBR1_EL1 holds the kernel (high-half) translation base; walked here for a kernel address.");
    } else {
        snprintf(out, cap,
                 "TTBR0_EL1 = user (low-half) translation base; TTBR1_EL1 holds the kernel (high-half) base.");
    }
#elif defined(__riscv)
    (void)kernel;
    int sv = res->paging_level == PAGING_LEVEL_5 ? 57 : res->paging_level == PAGING_LEVEL_4 ? 48
                                                                                            : 39;
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
#define PTE_PRESENT (1ULL << 0)
#define PTE_RW (1ULL << 1)
#define PTE_USER (1ULL << 2)
#define PTE_PWT (1ULL << 3)
#define PTE_PCD (1ULL << 4)
#define PTE_ACCESSED (1ULL << 5)
#define PTE_DIRTY (1ULL << 6)
#define PTE_PSE (1ULL << 7)
#define PTE_GLOBAL (1ULL << 8)
#define PTE_NX (1ULL << 63)

static void decode_pte_flags(char *out, int cap, unsigned long long e,
                             int huge_capable, int is_pte)
{
    int leaf = is_pte || (huge_capable && (e & PTE_PSE));
    int p = 0;

    out[0] = '\0';
    p = append_str(out, p, cap, "P");
    p = append_str(out, p, cap, (e & PTE_RW) ? " RW" : " RO");
    p = append_str(out, p, cap, (e & PTE_USER) ? " U" : " S");

    if (e & PTE_ACCESSED) {
        p = append_str(out, p, cap, " A");
    }
    if (leaf && (e & PTE_DIRTY)) {
        p = append_str(out, p, cap, " D");
    }
    if (e & PTE_PWT) {
        p = append_str(out, p, cap, " PWT");
    }
    if (e & PTE_PCD) {
        p = append_str(out, p, cap, " PCD");
    }
    if (e & PTE_GLOBAL) {
        p = append_str(out, p, cap, " G");
    }
    if (huge_capable && (e & PTE_PSE)) {
        p = append_str(out, p, cap, " PS");
    }
    if (is_pte && (e & PTE_PSE)) {
        p = append_str(out, p, cap, " PAT");
    }

    p = append_str(out, p, cap, (e & PTE_NX) ? " NX" : " X");
}

#elif defined(__aarch64__)

/* arm64 stage-1 descriptor attributes (4KB granule). */
#define A64_VALID (1ULL << 0)
#define A64_TABLE (1ULL << 1) /* at PUD/PMD: 1=table, 0=block */
#define A64_ATTRINDX_SHIFT 2
#define A64_ATTRINDX_MASK (7ULL << 2) /* MAIR index */
#define A64_USER (1ULL << 6)          /* AP[1]: 1=EL0 accessible */
#define A64_RDONLY (1ULL << 7)        /* AP[2]: 1=read-only */
#define A64_SH_SHIFT 8
#define A64_SH_MASK (3ULL << 8) /* SH[1:0] shareability */
#define A64_AF (1ULL << 10)     /* Access Flag (~ x86 Accessed) */
#define A64_NG (1ULL << 11)     /* not-Global (inverse of x86 G) */
#define A64_DBM (1ULL << 51)    /* Dirty Bit Management */
#define A64_CONT (1ULL << 52)   /* Contiguous range */
#define A64_PXN (1ULL << 53)    /* Privileged eXecute Never */
#define A64_UXN (1ULL << 54)    /* User eXecute Never */

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
    if (e & A64_AF) {
        p = append_str(out, p, cap, " AF");
    }
    p = append_str(out, p, cap, (e & A64_NG) ? " nG" : " G");
    p = append_str(out, p, cap, sh == 3 ? " ISH" : sh == 2 ? " OSH"
                                               : sh == 0   ? " NSH"
                                                           : " SH?");
    if (e & A64_CONT) {
        p = append_str(out, p, cap, " Cont");
    }
    if (e & A64_DBM) {
        p = append_str(out, p, cap, " DBM");
    }
    p = append_str(out, p, cap, (e & A64_PXN) ? " PXN" : " PX");
    p = append_str(out, p, cap, (e & A64_UXN) ? " UXN" : " UX");
    snprintf(ai, sizeof(ai), " AI=%u",
             (unsigned)((e & A64_ATTRINDX_MASK) >> A64_ATTRINDX_SHIFT));
    p = append_str(out, p, cap, ai);
    if (huge_capable && !(e & A64_TABLE)) {
        p = append_str(out, p, cap, " BLK");
    }
}

#elif defined(__riscv)

/* riscv PTE flags: low 8 bits are V R W X U G A D; PPN starts at bit 10. */
#define RV_V (1ULL << 0)
#define RV_R (1ULL << 1)
#define RV_W (1ULL << 2)
#define RV_X (1ULL << 3)
#define RV_U (1ULL << 4)
#define RV_G (1ULL << 5)
#define RV_A (1ULL << 6)
#define RV_D (1ULL << 7)

static void decode_pte_flags(char *out, int cap, unsigned long long e,
                             int huge_capable, int is_pte)
{
    int p = 0;

    (void)huge_capable;
    (void)is_pte;
    out[0] = '\0';
    p = append_str(out, p, cap, "V");
    if (e & RV_R) {
        p = append_str(out, p, cap, " R");
    }
    if (e & RV_W) {
        p = append_str(out, p, cap, " W");
    }
    if (e & RV_X) {
        p = append_str(out, p, cap, " X");
    }
    p = append_str(out, p, cap, (e & RV_U) ? " U" : " S");
    if (e & RV_G) {
        p = append_str(out, p, cap, " G");
    }
    if (e & RV_A) {
        p = append_str(out, p, cap, " A");
    }
    if (e & RV_D) {
        p = append_str(out, p, cap, " D");
    }
    /* No R/W/X set means this is a pointer to the next table, not a leaf. */
    if (!(e & (RV_R | RV_W | RV_X))) {
        p = append_str(out, p, cap, " (table)");
    }
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
        { "P4D", "Page 4 Directory", res->p4d_idx, res->p4d_base_phys,
          res->p4d_val, res->p4d_readback, 0, 0 },
        { "PUD", "Page Upper Directory", res->pud_idx, res->pud_base_phys,
          res->pud_val, res->pud_readback, 1, 0 },
        { "PMD", "Page Middle Directory", res->pmd_idx, res->pmd_base_phys,
          res->pmd_val, res->pmd_readback, 1, 0 },
        { "PTE", "Page Table Entry", res->pte_idx, res->pte_base_phys,
          res->pte_val, res->pte_readback, 0, 1 },
    };
    int use[5] = { 1, res->paging_level >= PAGING_LEVEL_5,
                   res->paging_level >= PAGING_LEVEL_4, 1, 1 };
    int n = 0;
    int i;

    for (i = 0; i < 5; ++i) {
        if (use[i]) {
            levels[n++] = all[i];
        }
    }
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

/* Emit a "+---+---+" rule sized to the label column and `col_widths[]`. */
static int emit_sep(char *buf, int off, int labelw, const int *col_widths, int ncols)
{
    char dash[64];
    int i;

    off += snprintf(buf + off, BUFFER_SIZE - off, "+%s+", fill(dash, labelw, '-'));
    for (i = 0; i < ncols; ++i) {
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s+", fill(dash, col_widths[i], '-'));
    }

    off += snprintf(buf + off, BUFFER_SIZE - off, "\n");
    return off;
}

/* Emit one "| label | cell | cell |" row with every cell centered. */
static int emit_row(char *buf, int off, const char *label, int labelw,
                    const char **cells, const int *col_widths, int ncols)
{
    char tmp[64];
    int i;

    off += snprintf(buf + off, BUFFER_SIZE - off, "|%s|",
                    center(tmp, sizeof(tmp), labelw, label));
    for (i = 0; i < ncols; ++i) {
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s|",
                        center(tmp, sizeof(tmp), col_widths[i], cells[i]));
    }
    off += snprintf(buf + off, BUFFER_SIZE - off, "\n");
    return off;
}

/* Format a byte count as an exact binary-unit string (e.g. "2 MiB", "64 KiB"). */
void human_size(char *out, size_t cap, unsigned long long bytes)
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
const char *leaf_level_name(unsigned int lvl)
{
    switch (lvl) {
    case PW_LEAF_PTE: return "PTE";
    case PW_LEAF_PMD: return "PMD";
    case PW_LEAF_PUD: return "PUD";
    case PW_LEAF_P4D: return "P4D";
    default:          return "?";
    }
}

/* Render the full walk report into `buf` (BUFFER_SIZE bytes); returns length. */
int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid,
                 int kernel_mode)
{
    int offset = 0;
    struct level_info levels[5];
    int level_count = select_levels(res, levels);
    int idx_bits = (int)res->page_shift - 3; /* 8-byte entries per table */
    int va_bits = (int)res->va_bits;
    char rdesc[256];

    /*
     * For a standard (non-contiguous) huge mapping, the translation stops at a
     * higher level and the page offset spans that level's size, so show only
     * the levels down to the leaf and widen the offset field to log2(page_size).
     * Contiguous / NAPOT leaves keep the base-granule breakdown (their span is
     * not a clean cut at a level boundary) and are called out in words instead.
     */
    int shown_levels = level_count;
    int offbits = (int)res->page_shift;

    if (res->is_valid && !res->is_contiguous &&
        res->mapping_level != PW_LEAF_PTE && res->mapping_level != PW_LEAF_NONE) {
        const char *target = leaf_level_name(res->mapping_level);
        int li;

        for (li = 0; li < level_count; ++li) {
            if (strcmp(levels[li].name, target) == 0) {
                break;
            }
        }
        /*
         * A huge leaf whose level is folded above the displayed levels (a PUD
         * leaf on a 3-level tree, or a P4D leaf below 5 levels) sits at the top
         * displayed level. Without this the trim is skipped and the report shows
         * spurious empty rows for the never-walked lower levels.
         */
        if (li >= level_count) {
            li = 0;
        }
        {
            unsigned long long s = res->page_size;

            shown_levels = li + 1;
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
    if (kernel_mode) {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
                           " Target       : kernel address space\n");
    } else {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
                           " Target PID   : %u\n", pid);
    }
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
    int field_count = 0;
    int shift_top = res->page_shift + (level_count - 1) * idx_bits;
    int i;

    snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d", 63, va_bits);
    fields[field_count].name = "Extension";
    fields[field_count].val = va_bits >= 64 ? 0 : (res->target_vaddr >> va_bits);
    fields[field_count].nbits = 64 - va_bits;
    ++field_count;

    for (i = 0; i < shown_levels; ++i) {
        int shift = res->page_shift + (level_count - 1 - i) * idx_bits;
        int nbits = (i == 0) ? (va_bits - shift_top) : idx_bits;

        snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d",
                 shift + nbits - 1, shift);
        fields[field_count].name = levels[i].name;
        fields[field_count].val = levels[i].idx;
        fields[field_count].nbits = nbits;
        ++field_count;
    }

    snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d", offbits - 1, 0);
    fields[field_count].name = "offset";
    fields[field_count].val = res->target_vaddr & ((1ULL << offbits) - 1);
    fields[field_count].nbits = offbits;
    ++field_count;

    char hexs[9][16];
    char raws[9][48];

    for (i = 0; i < field_count; ++i) {
        snprintf(hexs[i], sizeof(hexs[i]), "0x%0*llx", (fields[i].nbits + 3) / 4, fields[i].val);
        bits_to_str(raws[i], fields[i].val, fields[i].nbits);
    }

    /*
     * Index box: one column per field. Each column's width is the widest cell
     * in it (bits / name / hex / binary); every cell is centered to that width,
     * so the rows stay aligned even though their content sizes differ.
     */
    int col_widths[9];
    const char *bitscells[9];
    const char *namecells[9];
    const char *hexcells[9];
    const char *bincells[9];
    int labelw = (int)strlen("Bits") + 2;

    for (i = 0; i < field_count; ++i) {
        int w = (int)strlen(fields[i].bits);

        if ((int)strlen(fields[i].name) > w) {
            w = (int)strlen(fields[i].name);
        }
        if ((int)strlen(hexs[i]) > w) {
            w = (int)strlen(hexs[i]);
        }
        if ((int)strlen(raws[i]) > w) {
            w = (int)strlen(raws[i]);
        }

        col_widths[i] = w + 2;
        bitscells[i] = fields[i].bits;
        namecells[i] = fields[i].name;
        hexcells[i] = hexs[i];
        bincells[i] = raws[i];
    }

    offset = emit_sep(buf, offset, labelw, col_widths, field_count);
    offset = emit_row(buf, offset, "Bits", labelw, bitscells, col_widths, field_count);
    offset = emit_sep(buf, offset, labelw, col_widths, field_count);
    offset = emit_row(buf, offset, "IDX", labelw, namecells, col_widths, field_count);
    offset = emit_row(buf, offset, "VAL", labelw, hexcells, col_widths, field_count);
    offset = emit_row(buf, offset, "BIN", labelw, bincells, col_widths, field_count);
    offset = emit_sep(buf, offset, labelw, col_widths, field_count);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "\n");

    /*
     * Full 64-bit address, split on the page-table field boundaries. Each binary
     * group is placed at the exact column its BIN cell occupies in the table, so
     * the two rows line up even when a column's widest cell is its name rather
     * than its binary.
     */
    int binstart[9];
    int acc = 1 + labelw + 1; /* column where the first cell's content begins */

    for (i = 0; i < field_count; ++i) {
        int leftpad = (col_widths[i] - (int)strlen(raws[i])) / 2;

        binstart[i] = acc + leftpad;
        acc += col_widths[i] + 1;
    }

    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
                       " Target VAddr (64-bit, MSB -> LSB): 0x%016llx\n", res->target_vaddr);

    char sp[96];
    int cur = binstart[0] - 3; /* leave room for "-> " just before the first group */

    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "%s-> ", fill(sp, cur, ' '));
    cur += 3;
    for (i = 0; i < field_count; ++i) {
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
    for (i = 0; i < shown_levels; ++i) {
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
