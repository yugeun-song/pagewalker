obj-m += pagewalker.o
pagewalker-objs := pagewalker_device.o walk.o

PROFILE ?= debug
ifneq ($(KERNELRELEASE),)
include $(src)/profile.mk
endif

# Detect kernel build path. Override KDIR (and ARCH / CROSS_COMPILE) to build
# the module for arm64 or riscv64 against a prebuilt headers tree, e.g.:
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/arm64/headers
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
OBJCOPY = $(if $(LLVM),$(filter %/,$(LLVM))llvm-objcopy$(filter -%,$(LLVM)),$(CROSS_COMPILE)objcopy)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) PROFILE=$(PROFILE) $(if $(filter debug,$(PROFILE)),W=1) modules
ifeq ($(PROFILE),release)
	$(OBJCOPY) --only-keep-debug pagewalker.ko pagewalker.ko.debug
	$(OBJCOPY) --strip-debug --add-gnu-debuglink=pagewalker.ko.debug pagewalker.ko
else
	rm -f pagewalker.ko.debug
endif

clean:
	rm -rf *.o *.ko *.ko.debug *.mod *.mod.c *.mod.o .*.cmd .*.o.d .module-common.o modules.order \
		Module.symvers .tmp_versions
