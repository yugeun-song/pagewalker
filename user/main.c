#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>

#include "../include/pagewalk_common.h"

#define BUFFER_SIZE          16384
#define PID_MAX_FILE         "/proc/sys/kernel/pid_max"
#define DEFAULT_PID_MAX      32768
#define BASE_DECIMAL         10
#define BASE_HEX             16

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

static void print_step(char *buf, int *offset, const char *level_name,
                       unsigned long long table_base, unsigned long long idx,
                       unsigned long long entry_val, int is_valid_entry)
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
    *offset += snprintf(buf + *offset, BUFFER_SIZE - *offset,
        "  Status      : %s\n\n", is_valid_entry ? "Valid (Present)" : "Not Present / Empty");
}

int main(int argc, char *argv[])
{
    int fd = -1;
    int ret_code = EXIT_FAILURE;
    struct pagewalk_request req;
    char buf[BUFFER_SIZE];
    int offset = 0;

    char *endptr;
    long pid_long;
    unsigned long long vaddr_ull;
    int opt;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
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

    fd = open(PAGEWALK_PATH, O_RDWR);
    if (fd < 0) {
        perror("Error opening device");
        goto cleanup;
    }

    if (ioctl(fd, PAGEWALK_IOC_GET_INFO, &req) < 0) {
        perror("IOCTL Failed");
        goto cleanup;
    }

    struct pagewalk_result *res = &req.info;

    /* --- Report Header --- */
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "\n=========================================================\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " x86-64 Page Table Walk Report\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        "=========================================================\n");
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target PID   : %u\n", req.pid);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Target VAddr : 0x%016llx\n", res->target_vaddr);
    offset += snprintf(buf + offset, BUFFER_SIZE - offset,
        " Paging Mode  : %d-Level Paging\n", res->paging_level);

    /* --- Bit Breakdown --- */
    if (res->paging_level == PAGING_LEVEL_5) {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "+------+-------+-------+-------+-------+-------+-------+\n"
            "| Bits | 63-57 | 56-48 | 47-39 | 38-30 | 29-21 | 20-12 |\n"
            "+------+-------+-------+-------+-------+-------+-------+\n"
            "| IDX  |  Ext  |  PGD  |  P4D  |  PUD  |  PMD  |  PTE  |\n"
            "| VAL  |   %02llx  |  %03llx  |  %03llx  |  %03llx  |  %03llx  |  %03llx  |\n"
            "+------+-------+-------+-------+-------+-------+-------+\n\n",
            (res->target_vaddr >> 57) & 0x7f, res->pgd_idx, res->p4d_idx, res->pud_idx, res->pmd_idx, res->pte_idx);
    } else {
        offset += snprintf(buf + offset, BUFFER_SIZE - offset,
            "+------+-------+-------+-------+-------+-------+\n"
            "| Bits | 63-48 | 47-39 | 38-30 | 29-21 | 20-12 |\n"
            "+------+-------+-------+-------+-------+-------+\n"
            "| IDX  |  Ext  |  PGD  |  PUD  |  PMD  |  PTE  |\n"
            "| VAL  |  %04llx |  %03llx  |  %03llx  |  %03llx  |  %03llx  |\n"
            "+------+-------+-------+-------+-------+-------+\n\n",
            (res->target_vaddr >> 48) & 0xffff, res->pgd_idx, res->pud_idx, res->pmd_idx, res->pte_idx);
    }

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
               res->pgd_base_phys, res->pgd_idx, res->pgd_val, (res->pgd_val & 1));

    /* Step 2: P4D (5-level only) */
    if (res->paging_level == PAGING_LEVEL_5) {
        print_step(buf, &offset, "Step 2: P4D (Page 4 Directory)",
                   res->p4d_base_phys, res->p4d_idx, res->p4d_val, (res->p4d_val & 1));
    }

    /* Step 2/3: PUD */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 3: PUD (Page Upper Directory)" : "Step 2: PUD (Page Upper Directory)",
               res->pud_base_phys, res->pud_idx, res->pud_val, (res->pud_val & 1));

    /* Step 3/4: PMD */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 4: PMD (Page Middle Directory)" : "Step 3: PMD (Page Middle Directory)",
               res->pmd_base_phys, res->pmd_idx, res->pmd_val, (res->pmd_val & 1));

    /* Step 4/5: PTE */
    print_step(buf, &offset, (res->paging_level == 5) ? "Step 5: PTE (Page Table Entry)" : "Step 4: PTE (Page Table Entry)",
               res->pte_base_phys, res->pte_idx, res->pte_val, (res->pte_val & 1));

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

    printf("%s", buf);
    ret_code = EXIT_SUCCESS;

cleanup:
    if (fd >= 0)
        close(fd);
    return ret_code;
}
