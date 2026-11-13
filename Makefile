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
KALIAS_DIRS ?= /usr/src
ifneq ($(filter all debug release kernel index compdb,$(or $(MAKECMDGOALS),all)),)
KINFO := $(shell python3 kernel/ktree.py check --baseline 6.0 --arch '$(ARCH)' --cross '$(CROSS_COMPILE)' \
	--llvm '$(LLVM)' --cc '' '$(KDIR)')
ifneq ($(.SHELLSTATUS),0)
$(error $(KINFO))
endif
endif
kinfo = $(patsubst $(1)=%,%,$(filter $(1)=%,$(KINFO)))
ARCH := $(or $(ARCH),$(call kinfo,arch))
ifeq ($(CROSS_COMPILE)$(LLVM),)
CROSS_COMPILE := $(call kinfo,cross)
LLVM := $(call kinfo,llvm)
endif
KCC = $(or $(call kinfo,cc),$(if $(LLVM),$(filter %/,$(LLVM))clang$(filter -%,$(LLVM)),$(CROSS_COMPILE)gcc))
KTC = $(if $(ARCH),ARCH='$(ARCH)') $(if $(CROSS_COMPILE),CROSS_COMPILE='$(CROSS_COMPILE)') \
	$(if $(LLVM),LLVM='$(LLVM)') CC='$(KCC)'
KTARGET = $(KDIR) (ARCH=$(ARCH)$(if $(CROSS_COMPILE), CROSS_COMPILE=$(CROSS_COMPILE))$(if $(LLVM), LLVM=$(LLVM)))
KMAKE = $(MAKE) -C kernel KDIR='$(KDIR)' $(KTC)
KCOMPDB = $(MAKE) -C '$(KDIR)' M='$(CURDIR)/kernel' $(KTC) PROFILE='$(PROFILE)' \
	$(if $(filter debug,$(PROFILE)),W=1) compile_commands.json > /dev/null && \
	python3 kernel/clang-compdb.py --db kernel/compile_commands.json --kdir '$(KDIR)' --profile '$(PROFILE)' \
	--headers --link-dirs '$(KALIAS_DIRS)'
KREFRESH = $(if $(and $(wildcard kernel/compile_commands.json),$(filter-out index compdb,$(MK_GOALS))), \
	mv kernel/compile_commands.json kernel/compile_commands.json.old && \
	$(KCOMPDB) --previous kernel/compile_commands.json.old,:)

EXTRA_DEBUG := kmod-debug
EXTRA_RELEASE := kmod-release
EXTRA_COMPDB := kmod-compdb
EXTRA_CLEAN := kmod-clean
EXTRA_CLEAN_INDEX := kmod-clean-index
EXTRA_HELP_GOALS := '  kernel        the kernel module with the PROFILE flags (Kbuild and kernel/profile.mk)' \
	'  user          the user programs with the PROFILE flags'
EXTRA_HELP_VARIABLES := '  KDIR=<dir>             kernel build tree of the module (default: the running kernel,' \
	'                         else the newest under /lib/modules)' \
	'  ARCH=<arch>            target of the module (default: the architecture KDIR was built for)' \
	'  CROSS_COMPILE=, LLVM=  toolchain of the module (default: the one KDIR was built with)'

include build.mk

ifndef MK_SEQUENTIAL

.PHONY: kernel user kmod-debug kmod-release kmod-compdb kmod-clean kmod-clean-index

kernel: kmod-$(PROFILE)

user: $(foreach p,$(PROGRAMS),$(call mk_bin,$(PROFILE),$(p)))
	@echo "=> user ($(PROFILE)): $(call mk_count,$(PROGRAMS),program,programs) in $(BIN_ROOT)/$(TAG)-$(PROFILE)/"

kmod-debug:
	$(KMAKE) PROFILE=debug
	@echo "=> debug module: kernel/pagewalker.ko for $(KTARGET)"
	@$(if $(filter debug,$(PROFILE)),$(KREFRESH),:)

kmod-release:
	$(KMAKE) PROFILE=release
	@echo "=> release module: kernel/pagewalker.ko and its debug info kernel/pagewalker.ko.debug for $(KTARGET)"
	@$(if $(filter release,$(PROFILE)),$(KREFRESH),:)

kmod-compdb: kmod-$(PROFILE)
	@rm -f kernel/compile_commands.json
	@$(KCOMPDB)

kmod-clean:
	@$(MAKE) --no-print-directory -C kernel clean > /dev/null
	@echo "=> clean: removed the module build products in kernel/"

kmod-clean-index:
	@rm -f kernel/compile_commands.json
	@echo "=> clean-index: removed kernel/compile_commands.json"

endif
