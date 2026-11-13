STD := c99
PROGRAMS := pagewalkerctl selftest
pagewalkerctl_SRCS := user/pagewalkerctl.c user/report.c user/dump.c user/symbols.c user/read.c
selftest_SRCS := user/selftest.c
selftest_STATIC := 1

KVER ?= $(shell uname -r)
ifeq ($(origin KDIR),undefined)
KDIR := /lib/modules/$(KVER)/build
ifeq ($(wildcard $(KDIR)/Makefile),)
KDIR := $(lastword $(shell ls -d /lib/modules/*/build 2> /dev/null | sort -V))
endif
endif
KDIR_SYMLINK_DIRS ?= /usr/src
ifneq ($(filter all debug release kernel index compdb,$(or $(MAKECMDGOALS),all)),)
KDIR_INFO := $(shell python3 kernel/check-kernel-tree.py check --min-version 6.0 --arch '$(ARCH)' --cross '$(CROSS_COMPILE)' \
	--llvm '$(LLVM)' --cc '' '$(KDIR)')
ifneq ($(.SHELLSTATUS),0)
$(error $(KDIR_INFO))
endif
endif
kinfo = $(patsubst $(1)=%,%,$(filter $(1)=%,$(KDIR_INFO)))
ARCH := $(or $(ARCH),$(call kinfo,arch))
ifeq ($(CROSS_COMPILE)$(LLVM),)
CROSS_COMPILE := $(call kinfo,cross)
LLVM := $(call kinfo,llvm)
endif
ifeq ($(call kinfo,symvers)$(KBUILD_MODPOST_WARN),none)
$(error $(KDIR) has no Module.symvers or vmlinux.symvers, so the module cannot be checked against it; \
	build vmlinux in it first, or pass KBUILD_MODPOST_WARN=1 to compile anyway)
endif
EXTRA_SYMBOLS = $(if $(filter vmlinux,$(call kinfo,symvers)),KBUILD_EXTRA_SYMBOLS='$(KDIR)/vmlinux.symvers')
KCC = $(or $(call kinfo,cc),$(if $(LLVM),$(filter %/,$(LLVM))clang$(filter -%,$(LLVM)),$(CROSS_COMPILE)gcc))
MODULE_TOOLCHAIN = $(if $(ARCH),ARCH='$(ARCH)') $(if $(CROSS_COMPILE),CROSS_COMPILE='$(CROSS_COMPILE)') \
	$(if $(LLVM),LLVM='$(LLVM)') CC='$(KCC)'
KTARGET = $(KDIR) (ARCH=$(ARCH)$(if $(CROSS_COMPILE), CROSS_COMPILE=$(CROSS_COMPILE))$(if $(LLVM), LLVM=$(LLVM)))
KMAKE = $(MAKE) -C kernel KDIR='$(KDIR)' $(MODULE_TOOLCHAIN) $(EXTRA_SYMBOLS)
KCOMPDB = $(MAKE) -C '$(KDIR)' M='$(CURDIR)/kernel' $(MODULE_TOOLCHAIN) PROFILE='$(PROFILE)' \
	$(if $(filter debug,$(PROFILE)),W=1) compile_commands.json > /dev/null && \
	python3 kernel/clang-compdb.py --db kernel/compile_commands.json --kdir '$(KDIR)' --profile '$(PROFILE)' \
	--headers --symlink-dirs '$(KDIR_SYMLINK_DIRS)'
KREFRESH = $(if $(and $(wildcard kernel/compile_commands.json),$(filter-out index compdb,$(MK_GOALS))), \
	mv kernel/compile_commands.json kernel/compile_commands.json.old && \
	$(KCOMPDB) --previous kernel/compile_commands.json.old,:)

EXTRA_DEBUG := module-debug
EXTRA_RELEASE := module-release
EXTRA_COMPDB := module-compdb
EXTRA_CLEAN := module-clean
EXTRA_CLEAN_INDEX := module-clean-index
EXTRA_HELP_GOALS := '  kernel        the kernel module with the PROFILE flags (Kbuild and kernel/profile.mk)' \
	'  user          the user programs with the PROFILE flags'
EXTRA_HELP_VARIABLES := '  KDIR=<dir>             kernel build tree of the module (default: the running kernel,' \
	'                         else the newest under /lib/modules)' \
	'  ARCH=<arch>            target of the module (default: the architecture KDIR was built for)' \
	'  CROSS_COMPILE=, LLVM=  toolchain of the module (default: the one KDIR was built with)'

include build.mk

ifndef MK_SEQUENTIAL

.PHONY: kernel user module-debug module-release module-compdb module-clean module-clean-index

kernel: module-$(PROFILE)

user: $(foreach p,$(PROGRAMS),$(call mk_bin,$(PROFILE),$(p)))
	@echo "=> user ($(PROFILE)): $(call mk_count,$(PROGRAMS),program,programs) in $(BIN_DIR)/$(MK_TARGET)-$(PROFILE)/"

module-debug:
	$(KMAKE) PROFILE=debug
	@echo "=> debug module: kernel/pagewalker.ko for $(KTARGET)"
	@$(if $(filter debug,$(PROFILE)),$(KREFRESH),:)

module-release:
	$(KMAKE) PROFILE=release
	@echo "=> release module: kernel/pagewalker.ko and its debug info kernel/pagewalker.ko.debug for $(KTARGET)"
	@$(if $(filter release,$(PROFILE)),$(KREFRESH),:)

module-compdb: module-$(PROFILE)
	@rm -f kernel/compile_commands.json
	@$(KCOMPDB)

module-clean:
	@$(MAKE) --no-print-directory -C kernel clean > /dev/null
	@echo "=> clean: removed the module build products in kernel/"

module-clean-index:
	@rm -f kernel/compile_commands.json
	@echo "=> clean-index: removed kernel/compile_commands.json"

endif
