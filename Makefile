STD := c99
PROGRAMS := pagewalkerctl selftest
pagewalkerctl_SRCS := user/pagewalkerctl.c user/report.c user/dump.c user/symbols.c user/read.c
selftest_SRCS := user/selftest.c
selftest_STATIC := 1
FORMAT_SRCS := $(shell git ls-files -- 'user/*.c' 'user/*.h' 2> /dev/null)

KVER ?= $(shell uname -r)
ifeq ($(origin KDIR),undefined)
KDIR := /lib/modules/$(KVER)/build
ifeq ($(wildcard $(KDIR)/Makefile),)
KDIR := $(lastword $(shell ls -d /lib/modules/*/build 2> /dev/null | sort -V))
endif
endif
KALIAS_DIRS ?= /usr/src
KCC = $(if $(LLVM),$(filter %/,$(LLVM))clang$(filter -%,$(LLVM)),$(CROSS_COMPILE)gcc)
KMAKE = $(MAKE) -C kernel KDIR='$(KDIR)' CC='$(KCC)'

EXTRA_DEBUG := kmod-debug
EXTRA_RELEASE := kmod-release
EXTRA_COMPDB := kmod-compdb
EXTRA_CLEAN := kmod-clean
EXTRA_CLEAN_INDEX := kmod-clean-index
EXTRA_HELP_GOALS := '  kernel        the kernel module with the PROFILE flags (Kbuild and kernel/profile.mk)' \
	'  user          the user programs with the PROFILE flags'
EXTRA_HELP_VARIABLES := '  KDIR=<dir>             kernel build tree of the module (default: the running kernel,' \
	'                         else the newest under /lib/modules)' \
	'  LLVM=, CROSS_COMPILE=  toolchain of the module, as in Kbuild (default: gcc)'

include build.mk

ifndef MK_SEQUENTIAL

.PHONY: kernel user kmod-debug kmod-release kmod-compdb kmod-clean kmod-clean-index

kernel: kmod-$(PROFILE)

user: $(foreach p,$(PROGRAMS),$(call mk_bin,$(PROFILE),$(p)))
	@echo "=> user ($(PROFILE)): $(call mk_count,$(PROGRAMS),program,programs) in $(BIN_ROOT)/$(TAG)-$(PROFILE)/"

kmod-debug:
	$(KMAKE) PROFILE=debug
	@echo "=> debug module: kernel/pagewalker.ko for $(KDIR)"

kmod-release:
	$(KMAKE) PROFILE=release
	@echo "=> release module: kernel/pagewalker.ko and its debug info kernel/pagewalker.ko.debug for $(KDIR)"

kmod-compdb: kmod-$(PROFILE)
	@rm -f kernel/compile_commands.json
	@$(MAKE) -C '$(KDIR)' M='$(CURDIR)/kernel' CC='$(KCC)' PROFILE='$(PROFILE)' \
		$(if $(filter debug,$(PROFILE)),W=1) compile_commands.json > /dev/null
	@python3 kernel/clang-compdb.py --db kernel/compile_commands.json --kdir '$(KDIR)' --profile '$(PROFILE)' \
		--headers --link-dirs '$(KALIAS_DIRS)'

kmod-clean:
	@$(MAKE) --no-print-directory -C kernel clean > /dev/null
	@echo "=> clean: removed the module build products in kernel/"

kmod-clean-index:
	@rm -f kernel/compile_commands.json
	@echo "=> clean-index: removed kernel/compile_commands.json"

endif
