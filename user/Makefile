# CC is overridable for cross-compiling, e.g.:
#   make CC=aarch64-linux-gnu-gcc
#   make CC=riscv64-linux-gnu-gcc
CC ?= gcc
CFLAGS = -Wall -O2
TARGET = pagewalkerctl
SELFTEST = selftest
SRC = main.c

.PHONY: all selftest clean

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Self-contained, statically linked verifier (built with -DPW_SELFTEST). Run as
# PID 1 it loads the module and walks its own mapping; used for QEMU testing.
selftest:
	$(CC) $(CFLAGS) -DPW_SELFTEST -static -o $(SELFTEST) $(SRC)

clean:
	rm -f $(TARGET) $(SELFTEST)
