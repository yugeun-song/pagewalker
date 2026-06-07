#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>

#include "../include/pagewalker_common.h"

#define BUFFER_SIZE          16384
#define PID_MAX_FILE         "/proc/sys/kernel/pid_max"
#define DEFAULT_PID_MAX      32768
#define BASE_DECIMAL         10
#define BASE_HEX             16

/* x86-64 page-table entry flag bits (low 12 + NX). Bit 7 is PS at PMD/PUD, PAT at PTE. */
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

static inline void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-h] <pid> <virtual_address>\n", prog_name);
}

static unsigned int get_system_pid_max(void)
{
    FILE *f = fopen(PID_MAX_FILE, "r");
    unsigned int max = DEFAULT_PID_MAX;
    if (f) {
        if (fscanf(f, "%u", &max) != 1) max = DEFAULT_PID_MAX;
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

/*
 * Decode the flag bits of a present entry into a compact token list.
 * `huge_capable` is set for PUD/PMD (bit 7 = PS, marks a huge leaf); `is_pte`
 * is set for the PTE level (bit 7 = PAT). Dirty is only meaningful on a leaf.
 */
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
        if (readback == entry_val)
            *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
                "  Verify      : *(0x%llx) == 0x%llx  [kernel read-back OK]\n",
                entry_addr, entry_val);
        else
            *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
                "  Verify      : *(0x%llx) read 0x%llx != entry 0x%llx  [MISMATCH]\n",
                entry_addr, readback, entry_val);
    }

    if (is_valid_entry) {
        char flags[64];

        decode_pte_flags(flags, sizeof(flags), entry_val, huge_capable, is_pte);
        *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
            "  Flags       : %s\n", flags);
    }

    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Status      : %s\n\n", is_valid_entry ? "Valid (Present)" : "Not Present / Empty");
}

/* One address field: its bit range, short name, value and width in bits. */
struct addr_field {
    const char *bits;
    const char *name;
    unsigned long long val;
    int nbits;
};

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

    for (i = 0; i < n; ++i)
        out[i] = c;
    out[i] = '\0';
    return out;
}

/* Write the low `nbits` of `val` as '0'/'1' characters, MSB first. */
static void bits_to_str(char *out, unsigned long long val, int nbits)
{
    int i;

    for (i = 0; i < nbits; ++i)
        out[i] = ((val >> (nbits - 1 - i)) & 1ULL) ? '1' : '0';
    out[nbits] = '\0';
}

/* Emit a "+---+---+" rule sized to the label column and `colw[]`. */
static int emit_sep(char *buf, int off, int labelw, const int *colw, int ncols)
{
    char dash[64];
    int i;

    off += snprintf(buf + off, BUFFER_SIZE - off, "+%s+", fill(dash, labelw, '-'));
    for (i = 0; i < ncols; ++i)
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s+", fill(dash, colw[i], '-'));
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
    for (i = 0; i < ncols; ++i)
        off += snprintf(buf + off, BUFFER_SIZE - off, "%s|",
                        center(tmp, sizeof(tmp), colw[i], cells[i]));
    off += snprintf(buf + off, BUFFER_SIZE - off, "\n");
    return off;
}

/* Render the full walk report into `buf`; the definition lives below main(). */
static int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid);

int main(int argc, char *argv[])
{
    int fd = -1;
    int ret_code = EXIT_FAILURE;
    struct pagewalker_request req;
    char buf[BUFFER_SIZE];

    char *endptr;
    long pid_long;
    unsigned long long vaddr_ull;
    int opt;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind + 2 != argc) {
        fprintf(stderr, "Error: Missing arguments.\n");
        return EXIT_FAILURE;
    }

    errno = 0;
    pid_long = strtol(argv[optind], &endptr, BASE_DECIMAL);
    if (errno != 0 || *endptr != '\0' || pid_long <= 0) {
        fprintf(stderr, "Error: Invalid PID.\n");
        goto cleanup;
    }

    if ((unsigned long)pid_long > get_system_pid_max()) {
        fprintf(stderr, "Error: PID out of range.\n");
        goto cleanup;
    }
    req.pid = (unsigned int)pid_long;

    errno = 0;
    vaddr_ull = strtoull(argv[optind + 1], &endptr, BASE_HEX);
    if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "Error: Invalid Address.\n");
        goto cleanup;
    }
    req.info.target_vaddr = vaddr_ull;
    req.padding = 0;

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

    if (ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req) < 0) {
        switch (errno) {
        case ESRCH:
            fprintf(stderr, "Error: PID %u not found.\n", req.pid);
            break;
        case EADDRNOTAVAIL:
            fprintf(stderr, "Error: 0x%llx is not a canonical address.\n",
                    (unsigned long long)req.info.target_vaddr);
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

    build_report(buf, &req.info, req.pid);
    printf("%s", buf);
    ret_code = EXIT_SUCCESS;

cleanup:
    if (fd >= 0)
        close(fd);
    return ret_code;
}

/* Render the full walk report into `buf` (BUFFER_SIZE bytes); returns length. */
static int build_report(char *buf, const struct pagewalker_result *res, unsigned int pid)
{
    int offset = 0;

    /* --- Report Header --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "\n=========================================================\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " x86-64 Page Table Walk Report\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "=========================================================\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target PID   : %u\n", pid);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target VAddr : 0x%016llx\n", res->target_vaddr);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Paging Mode  : %d-Level Paging\n", res->paging_level);

    /* --- Address field breakdown --- */
    struct addr_field fields[9];
    int nf;
    int nidx;

    if (res->paging_level == PAGING_LEVEL_5) {
        const struct addr_field idx_fields[] = {
            { "63-57", "Extension", (res->target_vaddr >> 57) & 0x7f, 7 },
            { "56-48", "PGD", res->pgd_idx, 9 },
            { "47-39", "P4D", res->p4d_idx, 9 },
            { "38-30", "PUD", res->pud_idx, 9 },
            { "29-21", "PMD", res->pmd_idx, 9 },
            { "20-12", "PTE", res->pte_idx, 9 },
        };

        nidx = (int)(sizeof(idx_fields) / sizeof(idx_fields[0]));
        memcpy(fields, idx_fields, sizeof(idx_fields));
    } else {
        const struct addr_field idx_fields[] = {
            { "63-48", "Extension", (res->target_vaddr >> 48) & 0xffff, 16 },
            { "47-39", "PGD", res->pgd_idx, 9 },
            { "38-30", "PUD", res->pud_idx, 9 },
            { "29-21", "PMD", res->pmd_idx, 9 },
            { "20-12", "PTE", res->pte_idx, 9 },
        };

        nidx = (int)(sizeof(idx_fields) / sizeof(idx_fields[0]));
        memcpy(fields, idx_fields, sizeof(idx_fields));
    }

    /* The page offset closes out the 64 bits; it has no page-table index. */
    nf = nidx;
    fields[nf] = (struct addr_field){ "11-0", "offset", res->target_vaddr & 0xfff, 12 };
    ++nf;

    char hexs[9][8];
    char raws[9][20];

    for (int i = 0; i < nf; ++i) {
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

    for (int i = 0; i < nf; ++i) {
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
     * the two rows line up even when a column's widest cell is its name (e.g. the
     * 7-bit 5-level "Extension" field) rather than its binary.
     */
    int binstart[9];
    int acc = 1 + labelw + 1;   /* column where the first cell's content begins */

    for (int i = 0; i < nf; ++i) {
        int leftpad = (colw[i] - (int)strlen(raws[i])) / 2;

        binstart[i] = acc + leftpad;
        acc += colw[i] + 1;
    }

    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target VAddr (64-bit, MSB -> LSB): 0x%016llx\n", res->target_vaddr);

    char sp[64];
    int cur = binstart[0] - 3;   /* leave room for "-> " just before the first group */

    offset += snprintf(buf + offset, BUFFER_SIZE - offset, "%s-> ", fill(sp, cur, ' '));
    cur += 3;
    for (int i = 0; i < nf; ++i) {
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

    /* Step 0: CR3 */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "[Step 0: CR3 Register]\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "  Physical Addr : 0x%llx\n", res->cr3_phys);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "  Description   : Points to the Base of PGD Table\n\n");

    /* Step 1: PGD */
    print_step(buf, &offset, "Step 1: PGD (Page Global Directory)",
               res->pgd_base_phys, res->pgd_idx, res->pgd_val, res->pgd_readback,
               (res->pgd_val & 1), 0, 0);

    /* Step 2: P4D (5-level only) */
    if (res->paging_level == PAGING_LEVEL_5) {
        print_step(buf, &offset, "Step 2: P4D (Page 4 Directory)",
                   res->p4d_base_phys, res->p4d_idx, res->p4d_val, res->p4d_readback,
                   (res->p4d_val & 1), 0, 0);
    }

    /* Step 2/3: PUD (can be a 1GB huge leaf) */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 3: PUD (Page Upper Directory)" : "Step 2: PUD (Page Upper Directory)",
               res->pud_base_phys, res->pud_idx, res->pud_val, res->pud_readback,
               (res->pud_val & 1), 1, 0);

    /* Step 3/4: PMD (can be a 2MB huge leaf) */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 4: PMD (Page Middle Directory)" : "Step 3: PMD (Page Middle Directory)",
               res->pmd_base_phys, res->pmd_idx, res->pmd_val, res->pmd_readback,
               (res->pmd_val & 1), 1, 0);

    /* Step 4/5: PTE */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 5: PTE (Page Table Entry)" : "Step 4: PTE (Page Table Entry)",
               res->pte_base_phys, res->pte_idx, res->pte_val, res->pte_readback,
               (res->pte_val & 1), 0, 1);

    /* --- Final Verification --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "--------------------------------------------------------\n");

    if (res->is_valid) {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[FINAL RESULT]\n");
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Page Base Phys : 0x%llx\n", res->page_base_phys);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Offset         : 0x%llx\n", res->page_offset);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Final Phys Addr: 0x%llx\n\n", res->final_phys_addr);
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[VERIFICATION]\n");
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "  Content at Phys: 0x%016llx\n", res->value_at_phys);
    } else {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "[FINAL RESULT]\n  Translation Stopped (Page Fault / Not Mapped / Swapped Out)\n");
    }
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "--------------------------------------------------------\n");

    return offset;
}
