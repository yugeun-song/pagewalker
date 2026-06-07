# pagewalker

`pagewalker` is a Linux kernel module plus a user-space CLI that walk the x86-64
page tables of any running process and show, step by step, how a virtual address
is translated into a physical one. It exposes the raw paging structures
(PGD, P4D, PUD, PMD, PTE), decodes every entry, and verifies each step by reading
the physical slot back inside the kernel.

## Components

- **Kernel module** — `kernel/pagewalker.c` builds `pagewalker.ko`. It walks the
  target PID's page tables under `mmap_read_lock`, snapshots each level with the
  modern typed accessors (`pgdp_get`, `pmdp_get_lockless`, `ptep_get`), and
  serialises the PTE step with `pmd_lock` against khugepaged / `MADV_COLLAPSE`.
  It exposes `/dev/pagewalker` through `ioctl`.
- **User CLI** — `user/main.c` builds `pagewalkerctl`, which drives the ioctl and
  renders a detailed, column-aligned report.

## Features

- **4- and 5-level paging** — detected at runtime via `pgtable_l5_enabled()`;
  P4D is folded automatically on 4-level kernels.
- **Huge pages** — 2 MB (PMD leaf) and 1 GB (PUD leaf), including resident
  PROT_NONE / NUMA-balancing entries.
- **Correct stop conditions** — swap / migration / non-present entries are
  reported as "not mapped" instead of being mistaken for a physical address.
- **Address breakdown** — the virtual address is split into its fields (sign
  Extension, the page-table indices, the page offset) and shown in hex and
  binary, with the binary line aligned under the table's `BIN` row.
- **Per-entry flag decode** — `P RW/RO U/S A D G PS NX` decoded per level (bit 7
  is PS at PMD/PUD, PAT at PTE).
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
