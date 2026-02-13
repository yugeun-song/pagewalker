# x86-64 Page Table Walker

This project implements a Linux Kernel Module and a POSIX-compliant user-space CLI to inspect the hardware page table walking process for any running process. It bridges the gap between virtual memory addresses and physical RAM by exposing raw paging structures in Linux Kernel (PGD, P4D, PUD, PMD, PTE).

## Features

- **Architecture Support**: Native x86-64 support for both 4-Level (48-bit) and 5-Level (57-bit) paging.
- **Strict Validation**:
  - Validates PID against system limits (`/proc/sys/kernel/pid_max`).
  - Enforces Canonical Address form checks (kernel-side).
  - Handles huge pages (2MB, 1GB) correctly.
- **Robustness**:
  - Standard POSIX error codes (`ESRCH`, `EINVAL`, `EADDRNOTAVAIL`).
  - Safe resource management (RAII-style cleanup in user space).
  - Concurrency safety using `mmap_read_lock`.
- **Interface**:
  - `ioctl` based communication via character device `/dev/pagewalk`.
  - Detailed, bit-level breakdown of virtual addresses.

## Project Structure

- `kernel/`: Kernel module source (Kbuild).
- `user/`: User-space CLI tool (GCC).
- `include/`: Shared headers with strict type definitions.
- `bin/`: Output directory for binaries.

## Build Instructions

1. **Compile**:
```bash
make clean
make
```

2. **Load Module**:
```bash
sudo insmod bin/kernel/pagewalk.ko
```

## Usage

The tool requires root privileges to access the device node and inspect other processes.

```bash
sudo ./bin/user/pagewalker [OPTIONS] <PID> <VIRTUAL_ADDRESS>
```

### Options
- `-h, --help`: Display usage information and exit.

### Examples

**1. Inspect a specific address in a shell:**
```bash
sudo ./bin/user/pagewalker 1234 0x55a1b2c3d000
```

**2. Handling Errors (Invalid Input):**
```bash
sudo ./bin/user/pagewalker -1 0x1234
```text
Error: PID -1 is invalid.
Hint : PID must be a positive integer.
```

## Custom Integration

To integrate this page table walker into your own C/C++ application, include `pagewalk_common.h` and use the following core logic:

```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "pagewalk_common.h"

unsigned long long get_physical_address(int pid, unsigned long long vaddr)
{
    int fd;
    struct pagewalk_request req;

    fd = open(PAGEWALK_PATH, O_RDWR);
    if (fd < 0)
        return 0;

    req.pid = pid;
    req.info.target_vaddr = vaddr;

    if (ioctl(fd, PAGEWALK_IOC_GET_INFO, &req) < 0) {
        close(fd);
        return 0;
    }

    close(fd);

    if (req.info.isValid) {
        /* You can also access raw entries like req.info.pgd_val, etc. */
        return req.info.final_phys_addr;
    }

    return 0; /* Not mapped */
}
```

## Clean Up

To remove the kernel module:
```bash
sudo rmmod pagewalk
```
