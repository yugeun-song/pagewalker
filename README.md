# pagewalker

`pagewalker` is a Linux kernel module and a user-space CLI that walk the page
tables of any running process and show, step by step, how a virtual address is
translated into a physical one. It exposes the raw paging structures
(PGD, P4D, PUD, PMD, PTE), decodes every entry, and verifies each step by reading
the physical slot back inside the kernel.

Given a size it also dumps that many bytes of the mapped memory as a hexdump
(with an optional CJK/UTF-8 text gutter) or as a raw stream for piping. With
`-k` it walks and reads the **kernel's own** address space too — `_text`,
`memblock`, `swapper_pg_dir`, and any symbol from `/proc/kallsyms`. Every read
is fault-tolerant and, by default, refuses non-RAM (MMIO / reserved) frames, so
a read attempt never panics the machine or pokes a device register.

It builds from one source tree on **x86-64, arm64, and riscv64**: the walk and the
report are architecture-neutral, and each hardware-defined detail (root register,
entry-to-table extraction, paging-level detection, address representability, and
the PTE flag decode) is isolated behind a small `#ifdef`/arch helper. The
architecture is selected automatically by the kernel `CONFIG_*` / the compiler's
`__x86_64__` / `__aarch64__` / `__riscv` macros.

## Components

- **Kernel module** — `kernel/` builds `pagewalker.ko` from `main.c` (character
  device + `ioctl` dispatch), `walk.c` (the architecture-neutral page-table
  walk), and `read.c` (bulk read), with the per-arch specifics isolated in
  `arch.h`. It walks the
  target PID's page tables under `mmap_read_lock`, snapshots each level with the
  modern typed accessors (`pgdp_get`, `pmdp_get_lockless`, `ptep_get`), and
  serialises the PTE step with `pmd_lock` against khugepaged / `MADV_COLLAPSE`.
  It exposes `/dev/pagewalker` (root-only) through two `ioctl` commands:
  command 1 resolves one address and reports the single `u64` at it; command 2
  copies a run of bytes into a user buffer, re-walking each page (frames are
  contiguous only within a leaf) and checking every frame is System RAM. A
  kernel walk is rooted at the arch kernel table read straight from the hardware
  root register (`CR3` / `TTBR1_EL1` / `satp`), since `init_mm` is not exported.
- **User CLI** — `user/` builds `pagewalkerctl` from `main.c` (argument handling
  and dispatch), `report.c` (the walk report and per-arch flag decode), `dump.c`
  (hexdump / CJK gutter), `symbols.c` (kernel `/proc/kallsyms` and userspace ELF
  symbol resolution), and `read.c` (the command-2 driver). It drives the ioctls,
  resolves kernel symbols via `/proc/kallsyms`, and renders the walk report plus
  the hexdump / CJK / raw byte output.

## Features

- **3-, 4- and 5-level paging** — detected at runtime per arch (x86 LA57, arm64
  `pgtable_l4/l5_enabled()`, riscv Sv39/48/57); folded levels collapse
  automatically. The address breakdown adapts to the level count and page size
  reported by the kernel (so it is also correct for arm64 16K/64K granules).
- **ISA root register** — Step 0 reports the architecture's root translation
  register and what it points to: `CR3` (x86-64), `TTBR0_EL1` (arm64, the user
  half; `TTBR1_EL1` covers the kernel half), or `satp` (riscv, with its `Sv`
  MODE). The base value is `virt_to_phys(mm->pgd)` on every arch.
- **Huge pages, every size, every arch** — the leaf can sit at any level and the
  module reports the *true* mapped span: 4 KiB (PTE), 2 MiB (PMD), 1 GiB (PUD),
  the 512 GiB P4D terapage, **and the architecture's contiguous encodings** —
  arm64 cont-PTE (64 KiB) / cont-PMD (32 MiB) and riscv NAPOT (64 KiB). The size
  comes from the arch's own `*_leaf_size()` accessors, so the reported physical
  base and offset stay correct even for a contiguous / NAPOT page whose span
  exceeds the base granule (a plain `~PAGE_MASK` would drop the high offset bits,
  e.g. `va[15:12]` of a riscv 64 KiB NAPOT page). Resident PROT_NONE /
  NUMA-balancing huge entries stay valid; swap / migration huge entries are
  rejected. The result carries `page_size`, `mapping_level` (PTE/PMD/PUD/P4D) and
  `is_contiguous`; the report prints a `Mapped Page: <size> (leaf at <level>
  [, contiguous])` line and trims the address breakdown to the leaf with a
  widened page offset.
- **Correct stop conditions** — swap / migration / non-present entries are
  reported as "not mapped" instead of being mistaken for a physical address.
- **Per-entry flag decode** — architecture-specific, because the PTE bit layouts
  are disjoint (only the present/valid bit at bit 0 coincides): x86
  `P RW/RO U/S A D PWT PCD G PS PAT NX`, arm64
  `V RO/RW U/S AF nG SH Cont DBM PXN UXN AI=n BLK`, riscv `V R W X U G A D`.
- **Kernel read-back verification** — for every level the module independently
  re-reads the entry straight from its physical slot (`*(base + idx*8)` via
  `phys_to_virt`) and the CLI confirms it matches the value obtained through the
  page-table pointer.
- **Byte dump** — pass a size to copy that many bytes out and render them as a
  `hexdump -C`-style hexdump, a raw stream (`--raw`, for piping into `objdump` /
  `xxd` / `strings`), or a CJK/UTF-8-aware hexdump (`--cjk`) whose text gutter
  decodes multi-byte characters — even across line boundaries — and stays column
  aligned using a locale-independent `wcwidth`, so Korean/CJK renders correctly
  even in a bare static initramfs. Line width, grouping and case are tunable.
- **Kernel address space** — `-k` walks and reads the kernel's own memory rooted
  at the hardware kernel table (`CR3` / `TTBR1_EL1` / `satp`), resolving symbols
  such as `_text`, `memblock` or `swapper_pg_dir` through `/proc/kallsyms`. The
  same walk report is shown, labelled for the kernel root register.
- **Fault-tolerant, non-destructive reads** — every byte is fetched with
  `copy_from_kernel_nofault`, so an unmapped page, a hole or a bad frame
  truncates the dump instead of faulting. Each frame is vetted with
  `page_is_ram`, and a non-System-RAM (MMIO / reserved) page is refused by
  default — a read is never turned into a device-register access unless
  `--allow-mmio` is given. Reads are bounded and `cond_resched()`-paced, and the
  module never writes target memory.
- **Logging** — module load/unload and every request (mapped / stopped with the
  reason / rejected) are logged to the kernel ring buffer. Per-request logs are
  rate-limited, so the module stays safe under very high-frequency use.
- **Robust input handling** — PID-range and canonical-address checks; POSIX errno
  (`ESRCH`, `EINVAL`, `EADDRNOTAVAIL`) mapped to clear CLI messages.

## Verified under QEMU

The self-test (`make -C user selftest`) boots as PID 1 init in QEMU against the
prebuilt 6.12 research kernels and walks a known 4K / 64K / 2M / 1G mapping on
each arch. For every case it checks the reported `page_size`, `mapping_level`,
`is_contiguous`, and that the physical content read back equals the sentinel it
wrote — at an offset *above* the base granule, so a contiguous / NAPOT page
genuinely exercises the wide offset:

```
 case   x86-64        arm64                 riscv64
 ----   -----------   -------------------   -----------------
 4K     PTE           PTE                   PTE
 64K    n/a           PTE (cont-PTE)        PTE (NAPOT)
 2M     PMD           PMD                   PMD
 1G     PUD           PUD                   PUD
```

All applicable cases pass on all three arches (64 KiB has no x86-64 hugetlb
size, so it is reported as skipped there). riscv64 is run with QEMU
`-cpu rv64,svnapot=true` so the 64 KiB case maps through a NAPOT PTE.

## Project Structure

```
pagewalker/
├── include/pagewalker_common.h   # shared ioctl ABI (request / result, macros)
├── kernel/                       # module -> pagewalker.ko
│   ├── main.c                    #   character device + ioctl dispatch
│   ├── walk.c                    #   architecture-neutral page-table walk
│   ├── read.c                    #   bulk read (command 2) + System-RAM gate
│   ├── arch.h                    #   per-arch layer (root register, level fold)
│   └── pagewalker.h              #   internal cross-file interface
├── user/                         # CLI -> pagewalkerctl
│   ├── main.c                    #   argument handling + dispatch
│   ├── report.c                  #   walk report + per-arch flag decode
│   ├── dump.c                    #   hexdump / CJK-aware gutter
│   ├── symbols.c                 #   /proc/kallsyms + userspace ELF resolution
│   ├── read.c                    #   command-2 driver + size / address parsing
│   └── selftest.c                #   static QEMU self-test (make selftest)
└── Makefile                      # builds both (kernel Kbuild + gcc)
```

Build artifacts are produced next to their source (kernel Kbuild convention);
there is no separate output directory. Each tree carries its own `.clang-format`:
`kernel/` follows strict Linux kernel style, while `user/` uses a readable variant
that keeps braces on every control statement.

## Build

```bash
make            # builds kernel/pagewalker.ko and user/pagewalkerctl
make clean
```

The module compiles for whatever architecture the running kernel is — no Makefile
change needed. To cross-build for another arch, point the kernel `Makefile` at a
matching prebuilt headers tree and override the toolchain:

```bash
# kernel module (against a prebuilt arm64 / riscv64 headers tree)
make -C kernel ARCH=arm64   CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/arm64/headers
make -C kernel ARCH=riscv   CROSS_COMPILE=riscv64-linux-gnu- KDIR=/path/to/riscv64/headers

# user CLI
make -C user CC=aarch64-linux-gnu-gcc
make -C user CC=riscv64-linux-gnu-gcc

# statically-linked self-test: as PID 1 it loads the module and walks its own
# 4K / 64K / 2M / 1G mappings, asserting page_size, mapping_level, is_contiguous
# and the physical content for each (drives the QEMU multi-arch tests above)
make -C user selftest
```

## Usage

Root is required: `/dev/pagewalker` is created mode `0600`, and reading another
process's — or the kernel's — memory needs root anyway.

```bash
sudo insmod kernel/pagewalker.ko                      # creates /dev/pagewalker
sudo ./user/pagewalkerctl <pid> <address|symbol> [size]   # a process address space
sudo ./user/pagewalkerctl -k <symbol|0xaddr> [size]       # the kernel address space
sudo rmmod pagewalker
```

With no `size`, the tool prints the walk report only (backward compatible). With
a `size` it appends a byte dump of the mapped memory. The address is hex (an
optional `0x` prefix and leading zeros are fine — `0x000012ff50` is read as
`0x12ff50`); the size is decimal by default, or `0x`/`0b`-prefixed, with an
optional `K`/`M`/`G` suffix (`256`, `0x40`, `2K`).

For a process the target may instead be the **name of a global/static symbol**
in that process: the CLI reads `/proc/<pid>/maps` and the object's ELF symbol
table and computes the runtime address itself (so it works under PIE / ASLR).

Resolution reads `.symtab` first, then `.dynsym`. So to reference a variable by
name, build the program so the variable has an ELF symbol:

- Declare it at **file scope** — a global, or a file-scope `static` — not as a
  local. A stack/heap variable has no static address and no symbol, so it can
  only ever be reached by its runtime address (print it with `%p` and pass that
  hex value instead of a name).
- **Keep the symbol table** — do not `strip` the binary. A file-scope `static`
  lives only in `.symtab`, which `strip` removes; an exported global also appears
  in `.dynsym` and so survives stripping. A default `gcc`/`cc` build keeps
  `.symtab`, so no special flag is needed; just avoid `strip` / `-s`. Debug info
  (`-g`) is not required — the CLI reads the ELF symbol table, not DWARF.

For example, build this program with `cc -O2 -o demo demo.c` (unstripped):

```c
#include <stdio.h>
#include <unistd.h>

/* file scope: the compiler emits a symbol, so it is reachable by name */
char greeting[] = "hello, page tables";

int main(void)
{
    /* a local lives on the stack: no symbol, only a runtime address */
    char local[] = "i live on the stack";

    printf("pid=%d  &local=%p\n", getpid(), (void *)local);

    /* stay alive so another terminal can inspect us */
    while (1) {
        sleep(60);
    }
    return 0;
}
```

It prints, say, `pid=4242  &local=0x7ffe1c0a8b30`. Read the global by **name**
and the local by the **address** it printed:

```bash
sudo ./user/pagewalkerctl 4242 greeting 32 -c        # global, resolved by symbol
sudo ./user/pagewalkerctl 4242 0x7ffe1c0a8b30 24 -c  # local, by its %p address
```

Kernel symbol names differ per arch: the top-level table is `init_top_pgt` on
x86-64 and `swapper_pg_dir` on arm64.

### Options

| flag | effect |
|------|--------|
| `-k, --kernel` | target the kernel address space; the first argument is a symbol (resolved via `/proc/kallsyms`, e.g. `_text`, `memblock`, `swapper_pg_dir`) or a `0x` kernel address |
| `-x, --hex` | hexdump with an ASCII gutter (the default) |
| `-c, --cjk` | hexdump with a UTF-8 / CJK-aware text gutter |
| `-r, --raw` | raw bytes to stdout for piping (refuses a TTY unless `-F`) |
| `-w, --cols N` | bytes per line (1–256, default 16) |
| `-g, --group N` | bytes per hex group; `0` disables grouping (default 8) |
| `-u, --upper` | uppercase hex |
| `--no-report` | print only the byte dump, not the walk report |
| `--allow-mmio` | permit reads of non-System-RAM frames; **off by default**, so an MMIO / reserved page is refused rather than accessed (a device read can have a side effect) |

### Reading memory

```bash
# 64 bytes of the running kernel's text, as a hexdump
sudo ./user/pagewalkerctl -k _text 64

# a global symbol by name in a running process, resolved via its ELF (PIE-safe);
# environ is a libc global present in every process
sudo ./user/pagewalkerctl "$(pgrep -n bash)" environ 32 -c

# a process mapping by address; take a real range from /proc/<pid>/maps first, e.g.
#   awk 'NR==1{print $1}' /proc/1234/maps   ->  562300abc000-562300ace000
sudo ./user/pagewalkerctl 1234 0x562300abc000 256 -c

# the first 64 bytes of kernel text, then disassemble them
sudo ./user/pagewalkerctl -k _text 64 --raw | objdump -D -b binary -m i386:x86-64 -

# the live memblock allocator state (present on arches that keep it post-boot)
sudo ./user/pagewalkerctl -k memblock 128
```

The dump's offset column is relative to the start address; the absolute virtual
and physical bases (and the leaf size) are printed once in the dump banner, and
the full translation is in the walk report above it.

### Example

This sample is from x86-64. On arm64 the report header reads `arm64`, Step 0
shows `TTBR0_EL1`, and the flags use the arm64 token set; on riscv64 it reads
`riscv64`, shows `satp` with its `Sv` MODE, the `V R W X U G A D` flags, and a
3-row (Sv39) / 4-row (Sv48) / 5-row (Sv57) breakdown.

```text
=========================================================
 x86-64 Page Table Walk Report
=========================================================
 Target PID   : 1234
 Target VAddr : 0x00007ffeeec18460
 Paging Mode  : 4-Level Paging (VA 48-bit, page 4 KiB)
+------+------------------+-----------+-----------+-----------+-----------+--------------+
| Bits |      63-48       |   47-39   |   38-30   |   29-21   |   20-12   |     11-0     |
+------+------------------+-----------+-----------+-----------+-----------+--------------+
| IDX  |    Extension     |    PGD    |    PUD    |    PMD    |    PTE    |    offset    |
| VAL  |      0x0000      |   0x0ff   |   0x1fb   |   0x176   |   0x018   |    0x460     |
| BIN  | 0000000000000000 | 011111111 | 111111011 | 101110110 | 000011000 | 010001100000 |
+------+------------------+-----------+-----------+-----------+-----------+--------------+

 Target VAddr (64-bit, MSB -> LSB): 0x00007ffeeec18460
      -> 0000000000000000   011111111   111111011   101110110   000011000   010001100000

=== Translation Steps ===
...
[Step 4: PTE (Page Table Entry)]
  Table Base  : 0x285426000
  Index       : 0x18 (24)
  Calculation : 0x285426000 + (0x18 * 8) = 0x2854260c0
  Entry Value : 0x80000001f6989867
  Verify      : *(0x2854260c0) == 0x80000001f6989867  [kernel read-back OK]
  Flags       : P RW U A D NX
  Status      : Valid (Present)
--------------------------------------------------------
[FINAL RESULT]
  Mapped Page    : 4 KiB  (leaf at PTE)
  Page Base Phys : 0x1f6989000
  Offset         : 0x460
  Final Phys Addr: 0x1f6989460

[VERIFICATION]
  Content at Phys: 0x...  (u64, little-endian; bytes appear reversed in a dump)
--------------------------------------------------------
```

For a huge mapping the breakdown stops at the leaf and the offset widens to the
page size — e.g. a 1 GiB page shows `... | PGD | PUD | offset[29-0]`, the steps
end at the PUD leaf, and the final block reads
`Mapped Page : 1 GiB  (leaf at PUD)`; arm64 / riscv 64 KiB pages read
`64 KiB  (leaf at PTE, ARM64 contiguous ...)` / `(leaf at PTE, RISC-V NAPOT)`.

### Errors

```bash
sudo ./user/pagewalkerctl -1 0x1000
# Error: Invalid PID.
```

A non-existent PID or a non-canonical address is reported and the tool exits.

## Kernel Logs

Every operation is logged to `dmesg` (watch live with `sudo dmesg -w`):

```text
pagewalker: loaded: /dev/pagewalker ready (minor 123)
pagewalker: pid 1234 vaddr 0x7ffeeec18460 -> phys 0x1f6989460 [mapped via PTE 4K page]
pagewalker: pid 1234 vaddr 0x7faa60000000 -> phys 0x60000000 [mapped via PUD-level huge page]
pagewalker: pid 1234 vaddr 0x7f1200000000 : walk stopped [PTE not present (swapped out or unmapped)]
pagewalker: pid 99999999 : rejected (no such process)
pagewalker: unloaded
```

## Custom Integration

Include `pagewalker_common.h` and drive the ioctl directly:

```c
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "pagewalker_common.h"

unsigned long long get_physical_address(int pid, unsigned long long vaddr)
{
    struct pagewalker_request req = { .pid = pid };
    int fd = open(PAGEWALKER_PATH, O_RDWR);

    if (fd < 0)
        return 0;

    req.info.target_vaddr = vaddr;
    if (ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req) < 0) {
        close(fd);
        return 0;
    }
    close(fd);

    return req.info.is_valid ? req.info.final_phys_addr : 0;
}
```
