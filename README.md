# x86-64 Page Table Walker

This project implements a Linux Kernel Module and a POSIX-compliant user-space CLI to inspect the hardware page table walking process for any running process. It bridges the gap between virtual memory addresses and physical RAM by exposing raw paging structures (PGD, PUD, PMD, PTE).

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

cat << 'EOF' > README.md
# x86-64 Page Table Walker

This project implements a Linux Kernel Module and a POSIX-compliant user-space CLI to inspect the hardware page table walking process for any running process. It bridges the gap between virtual memory addresses and physical RAM by exposing raw paging structures (PGD, PUD, PMD, PTE).

## Features

- **Architecture Support**: Native x86-64 support for both 4-Level (48-bit) and 5-Level (57-bit) paging.
- **Strict Validation**: 
  - Validates PID against system limits (/proc/sys/kernel/pid_max).
  - Enforces Canonical Address form checks (kernel-side).
  - Handles huge pages (2MB, 1GB) correctly.
- **Robustness**: 
  - Standard POSIX error codes (ESRCH, EINVAL, EADDRNOTAVAIL).
  - Safe resource management (RAII-style cleanup in user space).
  - Concurrency safety using mmap_read_lock.
- **Interface**: 
  - ioctl based communication via character device /dev/pagewalk.
  - Detailed, bit-level breakdown of virtual addresses.

## Project Structure

- kernel/: Kernel module source (Kbuild).
- user/: User-space CLI tool (GCC).
- include/: Shared headers with strict type definitions.
- bin/: Output directory for binaries.

## Build Instructions

1. Compile:
   make clean
   make

2. Load Module:
   sudo insmod bin/kernel/pagewalk.ko

## Usage

The tool requires root privileges to access the device node and inspect other processes.

sudo ./bin/user/pagewalker [OPTIONS] <PID> <VIRTUAL_ADDRESS>

### Options
- -h, --help: Display usage information and exit.

### Examples

**1. Inspect a specific address in a shell:**
echo $$ 
sudo ./bin/user/pagewalker 1234 0x55a1b2c3d000

**2. Handling Errors (Invalid Input):**
sudo ./bin/user/pagewalker -1 0x1234
> Error: PID -1 is invalid.
> Hint : PID must be a positive integer.

## Clean Up

To remove the kernel module:
sudo rmmod pagewalk
