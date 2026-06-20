obj-m += pagewalker.o

# Detect kernel build path. Override KDIR (and ARCH / CROSS_COMPILE) to build
# the module for arm64 or riscv64 against a prebuilt headers tree, e.g.:
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/arm64/headers
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
