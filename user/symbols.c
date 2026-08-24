#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "symbols.h"
#include "read.h"

/*
 * Resolve a kernel address for -k. A 0x-prefixed argument is a raw address; any
 * other argument is a symbol name looked up in /proc/kallsyms (the only place a
 * module-less userspace can learn KASLR-relocated addresses). Returns 0 on
 * success, or: 1 = not found, 2 = resolved to 0 (kptr_restrict hides it from a
 * non-privileged reader), 3 = /proc/kallsyms unreadable, 4 = malformed 0x addr.
 */
int resolve_ksym(const char *arg, unsigned long long *out)
{
    char line[512];
    char name[256];
    char type;
    unsigned long long addr;
    FILE *f;
    int found = 0;

    if (arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
        return parse_vaddr(arg, out) == 0 ? 0 : 4;
    }

    f = fopen("/proc/kallsyms", "r");
    if (!f) {
        return 3;
    }

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3) {
            continue;
        }
        if (strcmp(name, arg) == 0) {
            found = 1;
            *out = addr;
            break;
        }
    }
    fclose(f);

    if (!found) {
        return 1;
    }
    if (addr == 0) {
        return 2;
    }
    return 0;
}

/*
 * Look one symbol up in an ELF64 object file. On success sets *st_value (the
 * symbol's link-time address) and *load_vaddr (the p_vaddr of the PT_LOAD that
 * covers file offset 0, i.e. the object's link base) and returns 1. Searches
 * .symtab first, then .dynsym. Every offset is bounds-checked against the mapped
 * size so a truncated or malformed file cannot walk off the end. *opened is set
 * to 1 when the file was reachable and mapped, so the caller can tell a truly-
 * missing symbol from an object it simply could not open. Returns 0 if the
 * symbol is absent or the file is not a usable ELF64 object.
 */
static int elf_lookup(const char *path, const char *name,
                      unsigned long long *st_value, unsigned long long *load_vaddr,
                      int *opened)
{
    int fd;
    struct stat file_stat;
    const unsigned char *base;
    const Elf64_Ehdr *elf_header;
    size_t file_size;
    int found = 0;
    unsigned i;

    *opened = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    if (fstat(fd, &file_stat) != 0 || (size_t)file_stat.st_size < sizeof(*elf_header)) {
        close(fd);
        return 0;
    }
    file_size = (size_t)file_stat.st_size;
    base = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        return 0;
    }
    *opened = 1; /* the object is reachable and mapped */

    elf_header = (const Elf64_Ehdr *)base;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0 ||
        elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        goto done;
    }

    /* Link base = p_vaddr of the PT_LOAD covering file offset 0. */
    *load_vaddr = 0;
    if (elf_header->e_phoff && elf_header->e_phnum &&
        elf_header->e_phoff + (size_t)elf_header->e_phnum * sizeof(Elf64_Phdr) <= file_size) {
        const Elf64_Phdr *prog_headers = (const Elf64_Phdr *)(base + elf_header->e_phoff);

        for (i = 0; i < elf_header->e_phnum; ++i) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_offset == 0) {
                *load_vaddr = prog_headers[i].p_vaddr;
                break;
            }
        }
    }

    if (!elf_header->e_shoff || !elf_header->e_shnum ||
        elf_header->e_shoff + (size_t)elf_header->e_shnum * sizeof(Elf64_Shdr) > file_size) {
        goto done;
    }

    {
        const Elf64_Shdr *sections = (const Elf64_Shdr *)(base + elf_header->e_shoff);
        int pass;

        /* Pass 0: SHT_SYMTAB (full table); pass 1: SHT_DYNSYM (fallback). */
        for (pass = 0; pass < 2 && !found; ++pass) {
            unsigned want = pass == 0 ? SHT_SYMTAB : SHT_DYNSYM;

            for (i = 0; i < elf_header->e_shnum && !found; ++i) {
                const Elf64_Sym *sym;
                const char *str;
                size_t sym_count, str_size, j;
                unsigned link = sections[i].sh_link;

                if (sections[i].sh_type != want || sections[i].sh_entsize == 0) {
                    continue;
                }
                if (link >= elf_header->e_shnum) {
                    continue;
                }
                if (sections[i].sh_offset + sections[i].sh_size > file_size ||
                    sections[link].sh_offset + sections[link].sh_size > file_size) {
                    continue;
                }

                sym = (const Elf64_Sym *)(base + sections[i].sh_offset);
                str = (const char *)(base + sections[link].sh_offset);
                str_size = sections[link].sh_size;
                sym_count = sections[i].sh_size / sizeof(Elf64_Sym);

                for (j = 0; j < sym_count; ++j) {
                    unsigned nameoff = sym[j].st_name;

                    if (nameoff >= str_size || sym[j].st_shndx == SHN_UNDEF) {
                        continue;
                    }
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
    munmap((void *)base, file_size);
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
int resolve_user_sym(unsigned int pid, const char *name,
                     unsigned long long *out, char *errbuf, size_t errcap)
{
    char mpath[64];
    char line[4096];
    char seen[64][512];
    int nseen = 0;
    int opened_any = 0;
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
     * Each object is opened through /proc/<pid>/root/<path>, i.e. the TARGET's own
     * filesystem view, so resolution stays correct when the target lives in a
     * different mount namespace / container / chroot. The bare caller-view path is
     * only a last-resort fallback if the rooted path cannot be opened.
     */
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off;
        char perms[8];
        char path[512];
        char rooted[600];
        unsigned long long st_value, load_vaddr;
        size_t plen;
        int opened = 0;
        int hit;

        path[0] = '\0';
        if (sscanf(line, "%llx-%llx %7s %llx %*x:%*x %*u %511[^\n]",
                   &start, &end, perms, &off, path) < 5) {
            continue;
        }
        if (off != 0 || path[0] != '/') {
            continue;
        }

        /* A deleted / replaced mapping reads "<path> (deleted)"; drop that tag. */
        plen = strlen(path);
        if (plen > 10 && strcmp(path + plen - 10, " (deleted)") == 0) {
            path[plen - 10] = '\0';
        }

        /* Skip a path already tried (an object has one offset-0 mapping anyway). */
        for (i = 0; i < nseen; ++i) {
            if (strcmp(seen[i], path) == 0) {
                break;
            }
        }
        if (i < nseen) {
            continue;
        }
        if (nseen < (int)(sizeof(seen) / sizeof(seen[0]))) {
            snprintf(seen[nseen++], sizeof(seen[0]), "%s", path);
        }

        /* Preset: the target's own filesystem view; fallback: the caller's. */
        snprintf(rooted, sizeof(rooted), "/proc/%u/root%s", pid, path);
        hit = elf_lookup(rooted, name, &st_value, &load_vaddr, &opened);
        if (!hit && !opened) {
            hit = elf_lookup(path, name, &st_value, &load_vaddr, &opened);
        }
        opened_any |= opened;

        if (hit) {
            *out = st_value + start - load_vaddr;
            fclose(f);
            return 0;
        }
    }
    fclose(f);

    if (opened_any) {
        snprintf(errbuf, errcap,
                 "symbol '%s' not found in PID %u's objects; a local/stack/heap "
                 "variable has no symbol - pass its runtime address (e.g. printed "
                 "with %%p)",
                 name, pid);
    } else {
        snprintf(errbuf, errcap,
                 "could not open any of PID %u's object files (different mount "
                 "namespace / container / chroot, or a deleted/replaced binary?) - "
                 "pass the variable's runtime address (e.g. printed with %%p), or "
                 "run from within the target's namespace",
                 pid);
    }
    return 1;
}
