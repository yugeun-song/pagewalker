#include "report.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__)
/* x86-64 entry flags (low 12 + NX). Bit 7 is PS at PMD/PUD, PAT at PTE. */
# define PTE_PRESENT (1ULL << 0)
# define PTE_RW (1ULL << 1)
# define PTE_USER (1ULL << 2)
# define PTE_PWT (1ULL << 3)
# define PTE_PCD (1ULL << 4)
# define PTE_ACCESSED (1ULL << 5)
# define PTE_DIRTY (1ULL << 6)
# define PTE_PSE (1ULL << 7)
# define PTE_GLOBAL (1ULL << 8)
# define PTE_NX (1ULL << 63)
#elif defined(__aarch64__)
/* arm64 stage-1 descriptor attributes (4KB granule). */
# define A64_VALID (1ULL << 0)
# define A64_TABLE (1ULL << 1) /* at PUD/PMD: 1=table, 0=block */
# define A64_ATTRINDX_SHIFT 2
# define A64_ATTRINDX_MASK (7ULL << 2) /* MAIR index */
# define A64_USER (1ULL << 6) /* AP[1]: 1=EL0 accessible */
# define A64_RDONLY (1ULL << 7) /* AP[2]: 1=read-only */
# define A64_SH_SHIFT 8
# define A64_SH_MASK (3ULL << 8) /* SH[1:0] shareability */
# define A64_AF (1ULL << 10) /* Access Flag (~ x86 Accessed) */
# define A64_NG (1ULL << 11) /* not-Global (inverse of x86 G) */
# define A64_DBM (1ULL << 51) /* Dirty Bit Management */
# define A64_CONT (1ULL << 52) /* Contiguous range */
# define A64_PXN (1ULL << 53) /* Privileged eXecute Never */
# define A64_UXN (1ULL << 54) /* User eXecute Never */
# define A64_TABLE_PXN (1ULL << 59)
# define A64_TABLE_UXN (1ULL << 60)
# define A64_TABLE_AP_SHIFT 61
# define A64_TABLE_AP_MASK (3ULL << 61)
# define A64_TABLE_NS (1ULL << 63)
#elif defined(__riscv)
/* riscv PTE flags: low 8 bits are V R W X U G A D; PPN starts at bit 10. */
# define RV_V (1ULL << 0)
# define RV_R (1ULL << 1)
# define RV_W (1ULL << 2)
# define RV_X (1ULL << 3)
# define RV_U (1ULL << 4)
# define RV_G (1ULL << 5)
# define RV_A (1ULL << 6)
# define RV_D (1ULL << 7)
# define RV_PBMT_SHIFT 61
# define RV_PBMT_MASK (3ULL << 61)
# define RV_NAPOT (1ULL << 63)
#endif /* defined(__x86_64__) */

/* One address field: its bit range, short name, value and width in bits. */
struct addr_field {
    char bits[24];
    const char *name;
    unsigned long long val;
    int bit_count;
};

/* One walked level: name + the values the kernel reported for it. */
struct level_info {
    const char *name;
    const char *long_name;
    unsigned long long idx;
    unsigned long long base_phys;
    unsigned long long val;
    unsigned long long readback;
    int is_huge_capable;
    int is_pte;
};

/* Append `text` to mut_out[pos], not exceeding cap; returns the new length. */
static int append_str(char *const mut_out, int pos, int cap, const char *const text)
{
    int i = 0;

    while (text[i] != '\0' && pos < cap - 1) {
        mut_out[pos] = text[i];
        ++pos;
        ++i;
    }
    mut_out[pos] = '\0';
    return pos;
}

static int __attribute__((format(printf, 3, 4))) append_formatted(char *const mut_out, int cap,
                                                                  const char *const fmt, ...)
{
    if (cap <= 0) {
        return 0;
    }

    va_list ap;

    va_start(ap, fmt);
    int length = vsnprintf(mut_out, (size_t)cap, fmt, ap);
    va_end(ap);
    if (length < 0) {
        mut_out[0] = '\0';
        return 0;
    }
    if (length >= cap) {
        return cap - 1;
    }
    return length;
}

/* One-line description of the root translation register for this arch. */
static void describe_root_reg(char *const mut_out, size_t cap,
                              const struct pagewalker_result *const res, int is_kernel)
{
#if defined(__x86_64__)
    snprintf(mut_out, cap,
             "CR3 holds the PGD/PML4 physical base; one root maps both the user and kernel halves.");
#elif defined(__aarch64__)
    if (is_kernel != 0) {
        snprintf(mut_out, cap,
                 "TTBR1_EL1 holds the kernel (high-half) translation base; walked here for a kernel address.");
    } else {
        snprintf(mut_out, cap,
                 "TTBR0_EL1 = user (low-half) translation base; TTBR1_EL1 holds the kernel (high-half) base.");
    }
#elif defined(__riscv)
    int va_bits = 39;

    if (res->paging_level == PAGING_LEVEL_5) {
        va_bits = 57;
    } else if (res->paging_level == PAGING_LEVEL_4) {
        va_bits = 48;
    }
    snprintf(mut_out, cap,
             "satp: MODE=Sv%d, root PPN=0x%llx (phys >> %u); one root for the whole address space.",
             va_bits, (unsigned long long)(res->root_table_phys >> res->page_shift),
             res->page_shift);
#endif /* defined(__x86_64__) */
}

/* Name of the root translation register actually used for this walk. */
static const char *get_root_reg_name(int is_kernel)
{
#if defined(__aarch64__)
    return (is_kernel != 0) ? "TTBR1_EL1" : "TTBR0_EL1";
#else
    return PW_ROOT_REG_NAME;
#endif
}

/*
 * Decode the flag bits of a present entry into a compact token list. The bit
 * layout is hardware-defined and disjoint across arches (only the present/valid
 * bit at bit 0 coincides), so this is the one decoder that must be per-arch.
 * `is_huge_capable` marks the PUD/PMD levels (block-capable); `is_pte` marks the
 * last level.
 */
#if defined(__x86_64__)

static void decode_pte_flags(char *const mut_out, int cap, unsigned long long entry,
                             int is_huge_capable, int is_pte)
{
    int is_leaf = is_pte != 0 || (is_huge_capable != 0 && (entry & PTE_PSE) != 0);
    int len = 0;

    mut_out[0] = '\0';
    len = append_str(mut_out, len, cap, "P");
    len = append_str(mut_out, len, cap, ((entry & PTE_RW) != 0) ? " RW" : " RO");
    len = append_str(mut_out, len, cap, ((entry & PTE_USER) != 0) ? " U" : " S");

    if ((entry & PTE_ACCESSED) != 0) {
        len = append_str(mut_out, len, cap, " A");
    }
    if (is_leaf != 0 && (entry & PTE_DIRTY) != 0) {
        len = append_str(mut_out, len, cap, " D");
    }
    if ((entry & PTE_PWT) != 0) {
        len = append_str(mut_out, len, cap, " PWT");
    }
    if ((entry & PTE_PCD) != 0) {
        len = append_str(mut_out, len, cap, " PCD");
    }
    if ((entry & PTE_GLOBAL) != 0) {
        len = append_str(mut_out, len, cap, " G");
    }
    if (is_huge_capable != 0 && (entry & PTE_PSE) != 0) {
        len = append_str(mut_out, len, cap, " PS");
    }
    if (is_pte != 0 && (entry & PTE_PSE) != 0) {
        len = append_str(mut_out, len, cap, " PAT");
    }

    len = append_str(mut_out, len, cap, ((entry & PTE_NX) != 0) ? " NX" : " X");
}

#elif defined(__aarch64__)

static void decode_pte_flags(char *const mut_out, int cap, unsigned long long entry,
                             int is_huge_capable, int is_pte)
{
    int len = 0;

    mut_out[0] = '\0';
    len = append_str(mut_out, len, cap, "V");

    char field_text[16];

    if (is_pte == 0 && (entry & A64_TABLE) != 0) {
        unsigned ap_table_bits = (unsigned)((entry & A64_TABLE_AP_MASK) >> A64_TABLE_AP_SHIFT);

        len = append_str(mut_out, len, cap, " TABLE");
        if ((entry & A64_TABLE_NS) != 0) {
            len = append_str(mut_out, len, cap, " NSTable");
        }
        if (ap_table_bits != 0) {
            snprintf(field_text, sizeof(field_text), " APTable=%u", ap_table_bits);
            len = append_str(mut_out, len, cap, field_text);
        }
        if ((entry & A64_TABLE_UXN) != 0) {
            len = append_str(mut_out, len, cap, " UXNTable");
        }
        if ((entry & A64_TABLE_PXN) != 0) {
            len = append_str(mut_out, len, cap, " PXNTable");
        }
        return;
    }
    len = append_str(mut_out, len, cap, ((entry & A64_RDONLY) != 0) ? " RO" : " RW");
    len = append_str(mut_out, len, cap, ((entry & A64_USER) != 0) ? " U" : " S");
    if ((entry & A64_AF) != 0) {
        len = append_str(mut_out, len, cap, " AF");
    }
    len = append_str(mut_out, len, cap, ((entry & A64_NG) != 0) ? " nG" : " G");

    unsigned sh_bits = (unsigned)((entry & A64_SH_MASK) >> A64_SH_SHIFT);
    const char *shareability = " SH?";

    if (sh_bits == 3) {
        shareability = " ISH";
    } else if (sh_bits == 2) {
        shareability = " OSH";
    } else if (sh_bits == 0) {
        shareability = " NSH";
    }
    len = append_str(mut_out, len, cap, shareability);
    if ((entry & A64_CONT) != 0) {
        len = append_str(mut_out, len, cap, " Cont");
    }
    if ((entry & A64_DBM) != 0) {
        len = append_str(mut_out, len, cap, " DBM");
    }
    len = append_str(mut_out, len, cap, ((entry & A64_PXN) != 0) ? " PXN" : " PX");
    len = append_str(mut_out, len, cap, ((entry & A64_UXN) != 0) ? " UXN" : " UX");
    snprintf(field_text, sizeof(field_text), " AI=%u",
             (unsigned)((entry & A64_ATTRINDX_MASK) >> A64_ATTRINDX_SHIFT));
    len = append_str(mut_out, len, cap, field_text);
    if (is_huge_capable != 0 && (entry & A64_TABLE) == 0) {
        len = append_str(mut_out, len, cap, " BLK");
    }
}

#elif defined(__riscv)

static void decode_pte_flags(char *const mut_out, int cap, unsigned long long entry,
                             int is_huge_capable, int is_pte)
{
    int len = 0;

    mut_out[0] = '\0';
    len = append_str(mut_out, len, cap, "V");
    if ((entry & RV_R) != 0) {
        len = append_str(mut_out, len, cap, " R");
    }
    if ((entry & RV_W) != 0) {
        len = append_str(mut_out, len, cap, " W");
    }
    if ((entry & RV_X) != 0) {
        len = append_str(mut_out, len, cap, " X");
    }
    len = append_str(mut_out, len, cap, ((entry & RV_U) != 0) ? " U" : " S");
    if ((entry & RV_G) != 0) {
        len = append_str(mut_out, len, cap, " G");
    }
    if ((entry & RV_A) != 0) {
        len = append_str(mut_out, len, cap, " A");
    }
    if ((entry & RV_D) != 0) {
        len = append_str(mut_out, len, cap, " D");
    }
    /* No R/W/X set means this is a pointer to the next table, not a leaf. */
    if ((entry & (RV_R | RV_W | RV_X)) == 0) {
        len = append_str(mut_out, len, cap, " (table)");
    } else {
        if ((entry & RV_NAPOT) != 0) {
            len = append_str(mut_out, len, cap, " NAPOT");
        }

        unsigned pbmt = (unsigned)((entry & RV_PBMT_MASK) >> RV_PBMT_SHIFT);

        if (pbmt != 0) {
            const char *pbmt_name = " PBMT=?";

            if (pbmt == 1) {
                pbmt_name = " PBMT=NC";
            } else if (pbmt == 2) {
                pbmt_name = " PBMT=IO";
            }
            len = append_str(mut_out, len, cap, pbmt_name);
        }
    }
}

#endif /* defined(__x86_64__) */

static void print_step(char *const mut_buf, int *const mut_offset, const char *const level_name,
                       unsigned long long table_base, unsigned long long idx,
                       unsigned long long entry_val, unsigned long long readback,
                       int is_valid_entry, int is_huge_capable, int is_pte)
{
    unsigned long long entry_addr = table_base + (idx * 8);

    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "[%s]\n", level_name);
    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "  Table Base  : 0x%llx\n", table_base);
    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "  Index       : 0x%llx (%llu)\n", idx, idx);
    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "  Calculation : 0x%llx + (0x%llx * 8) = 0x%llx\n",
                                    table_base, idx, entry_addr);
    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "  Entry Value : 0x%llx\n", entry_val);

    if (table_base != 0) {
        if (readback == entry_val) {
            *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                            "  Verify      : *(0x%llx) == 0x%llx  [kernel read-back OK]\n",
                                            entry_addr, entry_val);
        } else {
            *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                            "  Verify      : *(0x%llx) read 0x%llx != entry 0x%llx  [MISMATCH]\n",
                                            entry_addr, readback, entry_val);
        }
    }

    if (is_valid_entry != 0) {
        char flags[96];

        decode_pte_flags(flags, sizeof(flags), entry_val, is_huge_capable, is_pte);
        *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                        "  Flags       : %s\n", flags);
    }

    const char *status = (is_valid_entry != 0) ? "Valid (Present)" : "Not Present / Empty";

    *mut_offset += append_formatted(mut_buf + *mut_offset, BUFFER_SIZE - *mut_offset,
                                    "  Status      : %s\n\n", status);
}

/*
 * Select the active levels for this paging depth. PGD/PMD/PTE are always
 * present; PUD appears at >= 4 levels, P4D only at 5. Returns the count and
 * fills mut_levels[] top-to-bottom.
 */
static int select_levels(struct level_info *const mut_levels,
                         const struct pagewalker_result *const res)
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
    int is_used[5] = { 1, res->paging_level >= PAGING_LEVEL_5,
                       res->paging_level >= PAGING_LEVEL_4, 1, 1 };
    int count = 0;

    for (int i = 0; i < 5; ++i) {
        if (is_used[i] != 0) {
            mut_levels[count] = all[i];
            ++count;
        }
    }
    return count;
}

/* Center `text` within `width` columns; any odd surplus leans to the right. */
static const char *center(char *const mut_out, size_t out_size, int width, const char *const text)
{
    int len = (int)strlen(text);

    if (len >= width || (size_t)width + 1 > out_size) {
        snprintf(mut_out, out_size, "%.*s", width, text);
        return mut_out;
    }

    int left = (width - len) / 2;
    int right = width - len - left;

    memset(mut_out, ' ', (size_t)left);
    memcpy(mut_out + left, text, (size_t)len);
    memset(mut_out + left + len, ' ', (size_t)right);
    mut_out[width] = '\0';
    return mut_out;
}

/* Fill `mut_out` with `count` copies of `fill_char`, NUL-terminated. */
static const char *fill(char *const mut_out, int count, char fill_char)
{
    int i;

    for (i = 0; i < count; ++i) {
        mut_out[i] = fill_char;
    }

    mut_out[i] = '\0';
    return mut_out;
}

/* Write the low `bit_count` bits of `val` as '0'/'1' characters, MSB first. */
static void convert_bits_to_str(char *const mut_out, unsigned long long val, int bit_count)
{
    for (int i = 0; i < bit_count; ++i) {
        mut_out[i] = (((val >> (bit_count - 1 - i)) & 1ULL) != 0) ? '1' : '0';
    }

    mut_out[bit_count] = '\0';
}

/* Emit a "+---+---+" rule sized to the label column and `col_widths[]`. */
static int emit_sep(char *const mut_buf, int offset, int label_width, const int *const col_widths,
                    int column_count)
{
    char dash[64];

    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "+%s+",
                               fill(dash, label_width, '-'));
    for (int i = 0; i < column_count; ++i) {
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "%s+",
                                   fill(dash, col_widths[i], '-'));
    }

    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "\n");
    return offset;
}

/* Emit one "| label | cell | cell |" row with every cell centered. */
static int emit_row(char *const mut_buf, int offset, const char *const label, int label_width,
                    const char *const *const cells, const int *const col_widths, int column_count)
{
    char centered[64];

    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "|%s|",
                               center(centered, sizeof(centered), label_width, label));
    for (int i = 0; i < column_count; ++i) {
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "%s|",
                                   center(centered, sizeof(centered), col_widths[i], cells[i]));
    }
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "\n");
    return offset;
}

/* Format a byte count as an exact binary-unit string (e.g. "2 MiB", "64 KiB"). */
void format_human_size(char *const mut_out, size_t cap, unsigned long long bytes)
{
    static const char *s_units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    unsigned long long value = bytes;
    int unit = 0;

    while (unit < 4 && value >= 1024 && (value % 1024) == 0) {
        value /= 1024;
        ++unit;
    }
    snprintf(mut_out, cap, "%llu %s", value, s_units[unit]);
}

/* Short name of the page-table level that held the final leaf entry. */
const char *get_leaf_level_name(unsigned int level)
{
    switch (level) {
    case PW_LEAF_PTE:
        return "PTE";
    case PW_LEAF_PMD:
        return "PMD";
    case PW_LEAF_PUD:
        return "PUD";
    case PW_LEAF_P4D:
        return "P4D";
    default:
        return "?";
    }
}

/* Render the full walk report into `mut_buf` (BUFFER_SIZE bytes); returns length. */
int build_report(char *const mut_buf, const struct pagewalker_result *const res, unsigned int pid,
                 int is_kernel_mode)
{
    struct level_info levels[5];
    int level_count = select_levels(levels, res);
    int idx_bits = (int)res->page_shift - 3; /* 8-byte entries per table */
    int va_bits = (int)res->va_bits;

    /*
     * For a standard (non-contiguous) huge mapping, the translation stops at a
     * higher level and the page offset spans that level's size, so show only
     * the levels down to the leaf and widen the offset field to log2(page_size).
     * Contiguous / NAPOT leaves keep the base-granule breakdown (their span is
     * not a clean cut at a level boundary) and are called out in words instead.
     */
    int shown_levels = level_count;
    int offset_bits = (int)res->page_shift;

    if (res->is_valid != 0 && res->is_contiguous == 0 && res->mapping_level != PW_LEAF_PTE &&
        res->mapping_level != PW_LEAF_NONE) {
        const char *target = get_leaf_level_name(res->mapping_level);
        int leaf_index;

        for (leaf_index = 0; leaf_index < level_count; ++leaf_index) {
            if (strcmp(levels[leaf_index].name, target) == 0) {
                break;
            }
        }
        /*
         * A huge leaf whose level is folded above the displayed levels (a PUD
         * leaf on a 3-level tree, or a P4D leaf below 5 levels) sits at the top
         * displayed level. Without this the trim is skipped and the report shows
         * spurious empty rows for the never-walked lower levels.
         */
        if (leaf_index >= level_count) {
            leaf_index = 0;
        }
        {
            unsigned long long size = res->page_size;

            shown_levels = leaf_index + 1;
            offset_bits = 0;
            while (size > 1) {
                size >>= 1;
                ++offset_bits;
            }
        }
    }

    int offset = 0;

    /* --- Report Header --- */
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "\n=========================================================\n");
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               " %s Page Table Walk Report\n", PW_ARCH_NAME);
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "=========================================================\n");
    if (is_kernel_mode != 0) {
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   " Target       : kernel address space\n");
    } else {
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   " Target PID   : %u\n", pid);
    }
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               " Target VAddr : 0x%016llx\n", res->target_vaddr);
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               " Paging Mode  : %d-Level Paging (VA %d-bit, page %u KiB)\n",
                               res->paging_level, va_bits, (1U << res->page_shift) / 1024);

    /*
     * --- Address field breakdown ---
     * Built from the kernel-reported geometry (level count, VA width, page
     * size): an Extension field, one field per walked level (each idx_bits
     * wide, the top one trimmed to fill VA), then the page offset.
     */
    struct addr_field fields[9];
    int field_count = 0;
    int shift_top = (int)res->page_shift + ((level_count - 1) * idx_bits);

    snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d", 63, va_bits);
    fields[field_count].name = "Extension";
    fields[field_count].val = (va_bits >= 64) ? 0 : (res->target_vaddr >> va_bits);
    fields[field_count].bit_count = 64 - va_bits;
    ++field_count;

    for (int i = 0; i < shown_levels; ++i) {
        int shift = (int)res->page_shift + ((level_count - 1 - i) * idx_bits);
        int bit_count = (i == 0) ? (va_bits - shift_top) : idx_bits;

        snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d",
                 shift + bit_count - 1, shift);
        fields[field_count].name = levels[i].name;
        fields[field_count].val = levels[i].idx;
        fields[field_count].bit_count = bit_count;
        ++field_count;
    }

    snprintf(fields[field_count].bits, sizeof(fields[field_count].bits), "%d-%d",
             offset_bits - 1, 0);
    fields[field_count].name = "offset";
    fields[field_count].val = res->target_vaddr & ((1ULL << offset_bits) - 1);
    fields[field_count].bit_count = offset_bits;
    ++field_count;

    char hex_texts[9][16];
    char binary_texts[9][48];

    for (int i = 0; i < field_count; ++i) {
        snprintf(hex_texts[i], sizeof(hex_texts[i]), "0x%0*llx", (fields[i].bit_count + 3) / 4,
                 fields[i].val);
        convert_bits_to_str(binary_texts[i], fields[i].val, fields[i].bit_count);
    }

    /*
     * Index box: one column per field. Each column's width is the widest cell
     * in it (bits / name / hex / binary); every cell is centered to that width,
     * so the rows stay aligned even though their content sizes differ.
     */
    int col_widths[9];
    const char *bits_cells[9];
    const char *name_cells[9];
    const char *hex_cells[9];
    const char *binary_cells[9];
    int label_width = (int)strlen("Bits") + 2;

    for (int i = 0; i < field_count; ++i) {
        int width = (int)strlen(fields[i].bits);

        if ((int)strlen(fields[i].name) > width) {
            width = (int)strlen(fields[i].name);
        }
        if ((int)strlen(hex_texts[i]) > width) {
            width = (int)strlen(hex_texts[i]);
        }
        if ((int)strlen(binary_texts[i]) > width) {
            width = (int)strlen(binary_texts[i]);
        }

        col_widths[i] = width + 2;
        bits_cells[i] = fields[i].bits;
        name_cells[i] = fields[i].name;
        hex_cells[i] = hex_texts[i];
        binary_cells[i] = binary_texts[i];
    }

    offset = emit_sep(mut_buf, offset, label_width, col_widths, field_count);
    offset = emit_row(mut_buf, offset, "Bits", label_width, bits_cells, col_widths, field_count);
    offset = emit_sep(mut_buf, offset, label_width, col_widths, field_count);
    offset = emit_row(mut_buf, offset, "IDX", label_width, name_cells, col_widths, field_count);
    offset = emit_row(mut_buf, offset, "VAL", label_width, hex_cells, col_widths, field_count);
    offset = emit_row(mut_buf, offset, "BIN", label_width, binary_cells, col_widths, field_count);
    offset = emit_sep(mut_buf, offset, label_width, col_widths, field_count);
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "\n");

    /*
     * Full 64-bit address, split on the page-table field boundaries. Each binary
     * group is placed at the exact column its BIN cell occupies in the table, so
     * the two rows line up even when a column's widest cell is its name rather
     * than its binary.
     */
    int binary_columns[9];
    int cell_column = 1 + label_width + 1; /* column where the first cell's content begins */

    for (int i = 0; i < field_count; ++i) {
        int left_padding = (col_widths[i] - (int)strlen(binary_texts[i])) / 2;

        binary_columns[i] = cell_column + left_padding;
        cell_column += col_widths[i] + 1;
    }

    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               " Target VAddr (64-bit, MSB -> LSB): 0x%016llx\n",
                               res->target_vaddr);

    char spaces[96];
    int column = binary_columns[0] - 3; /* leave room for "-> " just before the first group */

    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "%s-> ",
                               fill(spaces, column, ' '));
    column += 3;
    for (int i = 0; i < field_count; ++i) {
        if (binary_columns[i] > column) {
            offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "%s",
                                       fill(spaces, binary_columns[i] - column, ' '));
            column = binary_columns[i];
        }
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "%s", binary_texts[i]);
        column += (int)strlen(binary_texts[i]);
    }
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset, "\n\n");

    /* --- Detailed Steps --- */
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "=== Translation Steps ===\n\n");

    /* Step 0: the arch root translation register. */
    char root_description[256];

    describe_root_reg(root_description, sizeof(root_description), res, is_kernel_mode);
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "[Step 0: %s Register]\n", get_root_reg_name(is_kernel_mode));
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "  Physical Addr : 0x%llx\n", res->root_table_phys);
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "  Description   : %s\n\n", root_description);

    /* Steps 1..N: one per walked level (down to the leaf for a huge page). */
    for (int i = 0; i < shown_levels; ++i) {
        char step_name[64];

        snprintf(step_name, sizeof(step_name), "Step %d: %s (%s)",
                 i + 1, levels[i].name, levels[i].long_name);
        print_step(mut_buf, &offset, step_name,
                   levels[i].base_phys, levels[i].idx, levels[i].val,
                   levels[i].readback, (int)(levels[i].val & 1),
                   levels[i].is_huge_capable, levels[i].is_pte);
    }

    /* --- Final Verification --- */
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "--------------------------------------------------------\n");

    if (res->is_valid != 0) {
        char page_size_text[32];

        format_human_size(page_size_text, sizeof(page_size_text), res->page_size);
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "[FINAL RESULT]\n");
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "  Mapped Page    : %s  (leaf at %s%s%s)\n", page_size_text,
                                   get_leaf_level_name(res->mapping_level),
                                   (res->is_contiguous != 0) ? ", " : "",
                                   (res->is_contiguous != 0) ? PW_CONT_TERM : "");
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "  Page Base Phys : 0x%llx\n", res->page_base_phys);
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "  Offset         : 0x%llx\n", res->page_offset);
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "  Final Phys Addr: 0x%llx\n\n", res->final_phys_addr);
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "[VERIFICATION]\n");
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "  Content at Phys: 0x%016llx  (u64, little-endian; bytes appear reversed in a dump)\n",
                                   res->value_at_phys);
    } else {
        offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                                   "[FINAL RESULT]\n  Translation Stopped (Page Fault / Not Mapped / Swapped Out)\n");
    }
    offset += append_formatted(mut_buf + offset, BUFFER_SIZE - offset,
                               "--------------------------------------------------------\n");

    return offset;
}
