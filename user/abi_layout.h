#ifndef USER_ABI_LAYOUT_H
#define USER_ABI_LAYOUT_H

#include <assert.h>
#include <stddef.h>

#include "../include/pagewalker_common.h"

/*
 * The ioctl structures must keep the layout the module was built with. The
 * module checks it at compile time; C99 has no _Static_assert, so the CLI checks
 * it here in debug builds.
 */
static inline void check_abi_layout(void)
{
    assert(sizeof(struct pagewalker_result) == 248);
    assert(offsetof(struct pagewalker_result, target_vaddr) == 0);
    assert(offsetof(struct pagewalker_result, paging_level) == 8);
    assert(offsetof(struct pagewalker_result, page_shift) == 12);
    assert(offsetof(struct pagewalker_result, va_bits) == 16);
    assert(offsetof(struct pagewalker_result, root_table_phys) == 24);
    assert(offsetof(struct pagewalker_result, pgd_idx) == 32);
    assert(offsetof(struct pagewalker_result, p4d_idx) == 40);
    assert(offsetof(struct pagewalker_result, pud_idx) == 48);
    assert(offsetof(struct pagewalker_result, pmd_idx) == 56);
    assert(offsetof(struct pagewalker_result, pte_idx) == 64);
    assert(offsetof(struct pagewalker_result, page_offset) == 72);
    assert(offsetof(struct pagewalker_result, pgd_val) == 80);
    assert(offsetof(struct pagewalker_result, p4d_val) == 88);
    assert(offsetof(struct pagewalker_result, pud_val) == 96);
    assert(offsetof(struct pagewalker_result, pmd_val) == 104);
    assert(offsetof(struct pagewalker_result, pte_val) == 112);
    assert(offsetof(struct pagewalker_result, pgd_readback) == 120);
    assert(offsetof(struct pagewalker_result, p4d_readback) == 128);
    assert(offsetof(struct pagewalker_result, pud_readback) == 136);
    assert(offsetof(struct pagewalker_result, pmd_readback) == 144);
    assert(offsetof(struct pagewalker_result, pte_readback) == 152);
    assert(offsetof(struct pagewalker_result, pgd_base_phys) == 160);
    assert(offsetof(struct pagewalker_result, p4d_base_phys) == 168);
    assert(offsetof(struct pagewalker_result, pud_base_phys) == 176);
    assert(offsetof(struct pagewalker_result, pmd_base_phys) == 184);
    assert(offsetof(struct pagewalker_result, pte_base_phys) == 192);
    assert(offsetof(struct pagewalker_result, page_base_phys) == 200);
    assert(offsetof(struct pagewalker_result, final_phys_addr) == 208);
    assert(offsetof(struct pagewalker_result, page_size) == 216);
    assert(offsetof(struct pagewalker_result, mapping_level) == 224);
    assert(offsetof(struct pagewalker_result, is_contiguous) == 228);
    assert(offsetof(struct pagewalker_result, value_at_phys) == 232);
    assert(offsetof(struct pagewalker_result, is_valid) == 240);
    assert(sizeof(struct pagewalker_request) == 256);
    assert(offsetof(struct pagewalker_request, pid) == 0);
    assert(offsetof(struct pagewalker_request, padding) == 4);
    assert(offsetof(struct pagewalker_request, info) == 8);
    assert(sizeof(struct pagewalker_read_request) == 296);
    assert(offsetof(struct pagewalker_read_request, pid) == 0);
    assert(offsetof(struct pagewalker_read_request, flags) == 4);
    assert(offsetof(struct pagewalker_read_request, vaddr) == 8);
    assert(offsetof(struct pagewalker_read_request, size) == 16);
    assert(offsetof(struct pagewalker_read_request, ubuf) == 24);
    assert(offsetof(struct pagewalker_read_request, bytes_read) == 32);
    assert(offsetof(struct pagewalker_read_request, stopped) == 40);
    assert(offsetof(struct pagewalker_read_request, pad) == 44);
    assert(offsetof(struct pagewalker_read_request, info) == 48);
}

#endif /* USER_ABI_LAYOUT_H */
