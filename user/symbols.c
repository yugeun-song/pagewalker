#define _POSIX_C_SOURCE 200809L

#include "symbols.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "read.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Look one symbol up in an ELF64 object file. On success sets *mut_st_value (the
 * symbol's link-time address) and *mut_load_vaddr (the p_vaddr of the PT_LOAD
 * that covers file offset 0, i.e. the object's link base) and returns 1. Searches
 * .symtab first, then .dynsym. Every offset is bounds-checked against the mapped
 * size so a truncated or malformed file cannot walk off the end. *mut_has_opened
 * is set to 1 when the file was reachable and mapped, so the caller can tell a
 * truly-missing symbol from an object it simply could not open. Returns 0 if the
 * symbol is absent or the file is not a usable ELF64 object.
 */
static int find_elf_symbol(unsigned long long *const mut_st_value,
                           unsigned long long *const mut_load_vaddr, int *const mut_has_opened,
                           const char *const path, const char *const name)
{
    *mut_has_opened = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    struct stat file_stat;

    if (fstat(fd, &file_stat) != 0 || (size_t)file_stat.st_size < sizeof(Elf64_Ehdr)) {
        close(fd);
        return 0;
    }

    size_t file_size = (size_t)file_stat.st_size;
    const unsigned char *base = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

    close(fd);
    if (base == MAP_FAILED) {
        return 0;
    }
    *mut_has_opened = 1; /* the object is reachable and mapped */

    const Elf64_Ehdr *elf_header = (const Elf64_Ehdr *)base;
    int has_found = 0;

    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0 ||
        elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        goto out_unmap;
    }

    /* Link base = p_vaddr of the PT_LOAD covering file offset 0. */
    *mut_load_vaddr = 0;
    if (elf_header->e_phoff != 0 && elf_header->e_phnum != 0 &&
        elf_header->e_phoff <= file_size &&
        (size_t)elf_header->e_phnum * sizeof(Elf64_Phdr) <= file_size - elf_header->e_phoff) {
        const Elf64_Phdr *prog_headers = (const Elf64_Phdr *)(base + elf_header->e_phoff);

        for (size_t i = 0; i < elf_header->e_phnum; ++i) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_offset == 0) {
                *mut_load_vaddr = prog_headers[i].p_vaddr;
                break;
            }
        }
    }

    if (elf_header->e_shoff == 0 || elf_header->e_shnum == 0 ||
        elf_header->e_shoff > file_size ||
        (size_t)elf_header->e_shnum * sizeof(Elf64_Shdr) > file_size - elf_header->e_shoff) {
        goto out_unmap;
    }

    {
        const Elf64_Shdr *sections = (const Elf64_Shdr *)(base + elf_header->e_shoff);

        /* Pass 0: SHT_SYMTAB (full table); pass 1: SHT_DYNSYM (fallback). */
        for (int pass = 0; pass < 2 && has_found == 0; ++pass) {
            unsigned wanted_type = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;

            for (size_t i = 0; i < elf_header->e_shnum && has_found == 0; ++i) {
                unsigned strtab_index = sections[i].sh_link;

                if (sections[i].sh_type != wanted_type || sections[i].sh_entsize == 0) {
                    continue;
                }
                if (strtab_index >= elf_header->e_shnum) {
                    continue;
                }
                if (sections[i].sh_offset > file_size ||
                    sections[i].sh_size > file_size - sections[i].sh_offset ||
                    sections[strtab_index].sh_offset > file_size ||
                    sections[strtab_index].sh_size > file_size - sections[strtab_index].sh_offset) {
                    continue;
                }

                const Elf64_Sym *symbols = (const Elf64_Sym *)(base + sections[i].sh_offset);
                const char *strtab = (const char *)(base + sections[strtab_index].sh_offset);
                size_t strtab_size = sections[strtab_index].sh_size;
                size_t symbol_count = sections[i].sh_size / sizeof(Elf64_Sym);

                for (size_t j = 0; j < symbol_count; ++j) {
                    unsigned name_offset = symbols[j].st_name;

                    if (name_offset >= strtab_size || symbols[j].st_shndx == SHN_UNDEF) {
                        continue;
                    }
                    /*
                     * The name must be NUL-terminated inside the string table,
                     * or strcmp() below would read past its end.
                     */
                    if (strnlen(strtab + name_offset, strtab_size - name_offset) ==
                        strtab_size - name_offset) {
                        continue;
                    }
                    if (strcmp(strtab + name_offset, name) == 0) {
                        *mut_st_value = symbols[j].st_value;
                        has_found = 1;
                        break;
                    }
                }
            }
        }
    }

out_unmap:
    munmap((void *)base, file_size);
    base = NULL;
    elf_header = NULL;
    return has_found;
}

/*
 * Resolve a kernel address for -k. A 0x-prefixed argument is a raw address; any
 * other argument is a symbol name looked up in /proc/kallsyms (the only place a
 * module-less userspace can learn KASLR-relocated addresses). Returns 0 on
 * success, or: 1 = not found, 2 = resolved to 0 (kptr_restrict hides it from a
 * non-privileged reader), 3 = /proc/kallsyms unreadable, 4 = malformed 0x addr.
 */
int resolve_ksym(unsigned long long *const mut_out, const char *const arg)
{
    if (arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
        return (parse_vaddr(mut_out, arg) == 0) ? 0 : 4;
    }

    FILE *file = fopen("/proc/kallsyms", "r");
    if (file == NULL) {
        return 3;
    }

    char line[512];
    unsigned long long addr;
    int has_found = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        char type;
        char name[256];

        if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3) {
            continue;
        }
        if (strcmp(name, arg) == 0) {
            has_found = 1;
            *mut_out = addr;
            break;
        }
    }
    fclose(file);
    file = NULL;

    if (has_found == 0) {
        return 1;
    }
    if (addr == 0) {
        return 2;
    }
    return 0;
}

/*
 * Resolve a symbol name to a runtime address inside process `pid`. This is done
 * entirely in userspace, as it should be: the kernel primitive only reads a
 * (pid, address) pair. We read /proc/pid/maps for each file-backed object's load
 * base (the mapping at file offset 0) and add the symbol's link-time value minus
 * the object's link base. It resolves functions and global/static data in the
 * executable and its shared libraries; a local, stack or heap variable has no
 * symbol and cannot be resolved. Returns 0 on success, or fills mut_errbuf and
 * returns non-zero (1 = not resolvable, 2 = /proc/pid/maps unreadable).
 */
int resolve_user_sym(unsigned long long *const mut_out, char *const mut_errbuf, size_t errbuf_size,
                     unsigned int pid, const char *const name)
{
    char maps_path[64];

    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);

    FILE *file = fopen(maps_path, "r");
    if (file == NULL) {
        snprintf(mut_errbuf, errbuf_size, "cannot read %s (process gone, or not permitted)",
                 maps_path);
        return 2;
    }

    /*
     * Collect the offset-0 mapping (the load base) of each distinct file-backed
     * object. That mapping's start minus the object's link base is the load bias.
     * Each object is opened through /proc/<pid>/root/<path>, i.e. the TARGET's own
     * filesystem view, so resolution stays correct when the target lives in a
     * different mount namespace / container / chroot. The bare caller-view path is
     * only a last-resort fallback if the rooted path cannot be opened.
     */
    char line[4096];
    char seen[64][512];
    size_t seen_count = 0;
    int has_opened_any = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long start;
        unsigned long long end;
        unsigned long long offset;
        char perms[8];
        char path[512];

        path[0] = '\0';
        if (sscanf(line, "%llx-%llx %7s %llx %*x:%*x %*u %511[^\n]", &start, &end, perms, &offset,
                   path) < 5) {
            continue;
        }
        if (offset != 0 || path[0] != '/') {
            continue;
        }

        /* A deleted / replaced mapping reads "<path> (deleted)"; drop that tag. */
        size_t path_len = strlen(path);

        if (path_len > 10 && strcmp(path + path_len - 10, " (deleted)") == 0) {
            path[path_len - 10] = '\0';
        }

        /* Skip a path already tried (an object has one offset-0 mapping anyway). */
        size_t i;

        for (i = 0; i < seen_count; ++i) {
            if (strcmp(seen[i], path) == 0) {
                break;
            }
        }
        if (i < seen_count) {
            continue;
        }
        if (seen_count < ARRAY_SIZE(seen)) {
            snprintf(seen[seen_count], sizeof(seen[0]), "%s", path);
            ++seen_count;
        }

        /* Preset: the target's own filesystem view; fallback: the caller's. */
        char rooted_path[600];
        unsigned long long st_value;
        unsigned long long load_vaddr;
        int has_opened = 0;

        snprintf(rooted_path, sizeof(rooted_path), "/proc/%u/root%s", pid, path);
        int has_found = find_elf_symbol(&st_value, &load_vaddr, &has_opened, rooted_path, name);
        if (has_found == 0 && has_opened == 0) {
            has_found = find_elf_symbol(&st_value, &load_vaddr, &has_opened, path, name);
        }
        has_opened_any |= has_opened;

        if (has_found != 0) {
            *mut_out = st_value + start - load_vaddr;
            fclose(file);
            file = NULL;
            return 0;
        }
    }
    fclose(file);
    file = NULL;

    if (has_opened_any != 0) {
        snprintf(mut_errbuf, errbuf_size,
                 "symbol '%s' not found in PID %u's objects; a local/stack/heap variable has no symbol - pass its runtime address (e.g. printed with %%p)",
                 name, pid);
    } else {
        snprintf(mut_errbuf, errbuf_size,
                 "could not open any of PID %u's object files (different mount namespace / container / chroot, or a deleted/replaced binary?) - pass the variable's runtime address (e.g. printed with %%p), or run from within the target's namespace",
                 pid);
    }
    return 1;
}
