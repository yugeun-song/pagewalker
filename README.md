# pagewalker

`pagewalker` is a Linux kernel module plus a user-space CLI that walk the page
tables of any running process and show, step by step, how a virtual address is
translated into a physical one. It exposes the raw paging structures
(PGD, P4D, PUD, PMD, PTE), decodes every entry, and verifies each step by reading
the physical slot back inside the kernel.

It builds from one source tree on **x86-64, arm64, and riscv64**: the walk and the
report are architecture-neutral, and each hardware-defined detail (root register,
entry-to-table extraction, paging-level detection, address representability, and
the PTE flag decode) is isolated behind a small `#ifdef`/arch helper. The
architecture is selected automatically by the kernel `CONFIG_*` / the compiler's
`__x86_64__` / `__aarch64__` / `__riscv` macros.

## Components

- **Kernel module** — `kernel/pagewalker.c` builds `pagewalker.ko`. It walks the
  target PID's page tables under `mmap_read_lock`, snapshots each level with the
  modern typed accessors (`pgdp_get`, `pmdp_get_lockless`, `ptep_get`), and
  serialises the PTE step with `pmd_lock` against khugepaged / `MADV_COLLAPSE`.
  It exposes `/dev/pagewalker` through `ioctl`.
- **User CLI** — `user/main.c` builds `pagewalkerctl`, which drives the ioctl and
  renders a detailed, column-aligned report.

## Features

- **3-, 4- and 5-level paging** — detected at runtime per arch (x86 LA57, arm64
  `pgtable_l4/l5_enabled()`, riscv Sv39/48/57); folded levels collapse
  automatically. The address breakdown adapts to the level count and page size
  reported by the kernel (so it is also correct for arm64 16K/64K granules).
- **ISA root register** — Step 0 reports the architecture's root translation
  register and what it points to: `CR3` (x86-64), `TTBR0_EL1` (arm64, the user
  half; `TTBR1_EL1` covers the kernel half), or `satp` (riscv, with its `Sv`
  MODE). The base value is `virt_to_phys(mm->pgd)` on every arch.
- **Huge pages** — 2 MB (PMD leaf) and 1 GB (PUD leaf), including resident
  PROT_NONE / NUMA-balancing entries.
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
- **Logging** — module load/unload and every request (mapped / stopped with the
  reason / rejected) are logged to the kernel ring buffer. Per-request logs are
  rate-limited, so the module stays safe under very high-frequency use.
- **Robust input handling** — PID-range and canonical-address checks; POSIX errno
  (`ESRCH`, `EINVAL`, `EADDRNOTAVAIL`) mapped to clear CLI messages.

## Project Structure

```
pagewalker/
├── include/pagewalker_common.h   # shared ioctl ABI (request / result, macros)
├── kernel/pagewalker.c           # kernel module -> pagewalker.ko
├── user/main.c                   # user CLI       -> pagewalkerctl
└── Makefile                      # builds both (kernel Kbuild + gcc)
```

Build artifacts are produced next to their source (kernel Kbuild convention);
there is no separate output directory.

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

# statically-linked self-test (loads the module + walks its own page; for QEMU)
make -C user selftest
```

## Usage

Root is required to open the device and inspect other processes.

```bash
sudo insmod kernel/pagewalker.ko           # creates /dev/pagewalker
sudo ./user/pagewalkerctl <PID> <0xVADDR>
sudo rmmod pagewalker
```

The address accepts an optional `0x` prefix and leading zeros
(`0x000012ff50` is read as `0x12ff50`).

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
 Paging Mode  : 4-Level Paging
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
  Page Base Phys : 0x1f6989000
  Offset         : 0x460
  Final Phys Addr: 0x1f6989460
--------------------------------------------------------
```

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
pagewalker: pid 1234 vaddr 0x7ffeeec18460 -> phys 0x1f6989460 [mapped via 4K page]
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
