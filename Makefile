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

define PW_DROP_GCC_ONLY_FLAGS
import json, os, shlex, shutil, subprocess
from concurrent.futures import ThreadPoolExecutor
clang = os.environ["CLANG"]
p = "kernel/compile_commands.json"
db = json.load(open(p))
head = f"=> {p}: {len(db)} entries with the {os.environ['PROFILE']} flags for {os.environ['KDIR']}"
if shutil.which(clang) is None:
    print(f"{head}, gcc-only flags kept, {clang} not found")
    raise SystemExit
takes_value = {"-include", "-isystem", "-o", "-MF", "-x", "-idirafter", "-imacros"}
def target(args):
    name = os.path.basename(args[0])
    return name[: -len("-gcc")] if name.endswith("-gcc") else None
def flags(args):
    value = False
    for a in args[1:]:
        if value:
            value = False
        elif a in takes_value:
            value = True
        elif a.startswith("-") and not a.startswith(("-I", "-D", "-U", "-Wp,")) and a not in ("-c", "-nostdinc"):
            yield a
def accepted(key):
    flag, triple = key
    argv = [clang, "-fsyntax-only", "-x", "c", "-c", os.devnull, "-Werror=unknown-warning-option",
            "-Werror=ignored-optimization-argument"]
    if triple:
        argv.append("--target=" + triple)
    return subprocess.run(argv + [flag], capture_output=True).returncode == 0
for e in db:
    if "command" in e:
        e["arguments"] = shlex.split(e.pop("command"))
keys = {(f, target(e["arguments"])) for e in db for f in flags(e["arguments"])}
with ThreadPoolExecutor(os.cpu_count()) as pool:
    verdict = dict(zip(keys, pool.map(accepted, keys)))
for e in db:
    t = target(e["arguments"])
    e["arguments"] = e["arguments"][:1] + [a for a in e["arguments"][1:] if verdict.get((a, t), True)]
json.dump(db, open(p, "w"), indent=2)
dropped = sorted({f for (f, _), ok in verdict.items() if not ok})
print(f"{head}, {len(dropped)} gcc-only flags dropped")
for f in dropped:
    print(f"  dropped {f}")
endef
export PW_DROP_GCC_ONLY_FLAGS

kmod-compdb: kmod-$(PROFILE)
	@python3 $(KDIR)/scripts/clang-tools/gen_compile_commands.py -d kernel -o kernel/compile_commands.json
	@printf '%s\n' "$$PW_INJECT_HDR_ENTRIES" | python3 -
	@printf '%s\n' "$$PW_DROP_GCC_ONLY_FLAGS" | CLANG='$(CLANG)' PROFILE='$(PROFILE)' KDIR='$(KDIR)' python3 -

kmod-clean:
	@$(MAKE) --no-print-directory -C kernel clean > /dev/null
	@echo "=> clean: removed the module build products in kernel/"

kmod-clean-index:
	@rm -f kernel/compile_commands.json
	@echo "=> clean-index: removed kernel/compile_commands.json"

endif
