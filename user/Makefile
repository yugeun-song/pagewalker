# CC is overridable for cross-compiling, e.g.:
#   make CC=aarch64-linux-gnu-gcc
#   make CC=riscv64-linux-gnu-gcc
CC ?= gcc
CFLAGS = -Wall -O2
TARGET = pagewalkerctl
SELFTEST = selftest

# The CLI links every unit; the self-test needs only the report renderer.
CLI_SRC = pagewalkerctl.c report.c dump.c symbols.c read.c
SELFTEST_SRC = selftest.c

.PHONY: all selftest clean

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(CLI_SRC)

# Self-contained, statically linked verifier. Run as PID 1 it loads the module
# and walks its own mapping; used for QEMU testing.
selftest:
	$(CC) $(CFLAGS) -static -o $(SELFTEST) $(SELFTEST_SRC)

clean:
	rm -f $(TARGET) $(SELFTEST)
