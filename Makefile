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
KCC = $(if $(LLVM),$(filter %/,$(LLVM))clang$(filter -%,$(LLVM)),$(CROSS_COMPILE)gcc)
KMAKE = $(MAKE) -C kernel KDIR='$(KDIR)' CC='$(KCC)'

EXTRA_DEBUG := kmod-debug
EXTRA_RELEASE := kmod-release
EXTRA_COMPDB := kmod-compdb
EXTRA_CLEAN := kmod-clean
EXTRA_CLEAN_INDEX := kmod-clean-index

include mk/c.mk

ifndef MK_SEQUENTIAL

.PHONY: kernel user kmod-debug kmod-release kmod-compdb kmod-clean kmod-clean-index

kernel: kmod-debug

user: $(foreach p,$(PROGRAMS),$(call mk_bin,debug,$(p)))

kmod-debug:
	$(KMAKE) PROFILE=debug

kmod-release:
	$(KMAKE) PROFILE=release

# Give clangd an explicit command for the kernel headers as well, cloned from
# walk.c, so opening arch.h / walk.h on their own still resolves the kernel
# include paths and CONFIG_* macros. Without it clangd parses a bare header with
# no command and reports spurious 'linux/mm.h not found' / 'unsupported
# architecture' errors that never occur in a real build.
define PW_INJECT_HDR_ENTRIES
import json, os
p = "kernel/compile_commands.json"
db = json.load(open(p))
w = next(e for e in db if e["file"].endswith("/walk.c"))
b = os.path.dirname(w["file"])
have = {e["file"] for e in db}
for h in ("arch.h", "walk.h"):
    f = os.path.join(b, h)
    if f in have:
        continue
    e = dict(w)
    e["file"] = f
    if "arguments" in e:
        a = [x for x in e["arguments"] if x != "-xc"]
        e["arguments"] = [a[0], "-xc"] + [(f if x.endswith("/walk.c") else x) for x in a[1:]]
    if "command" in e:
        e["command"] = e["command"].replace(" -c ", " -xc -c ").replace("walk.c", h)
    db.append(e)
json.dump(db, open(p, "w"), indent=2)
endef
export PW_INJECT_HDR_ENTRIES

kmod-compdb: kmod-debug
	python3 $(KDIR)/scripts/clang-tools/gen_compile_commands.py -d kernel -o kernel/compile_commands.json
	printf '%s\n' "$$PW_INJECT_HDR_ENTRIES" | python3 -

kmod-clean:
	$(MAKE) -C kernel clean

kmod-clean-index:
	rm -f kernel/compile_commands.json

endif
