.PHONY: all clean tags cscope clangd compile_commands.json user kernel

# The default build produces only the binaries (module + CLI). Build the source
# indexes explicitly with `make tags cscope clangd`; `make clean` removes them.
all: kernel user

# Kernel build directory, shared by the module build and the clangd database.
# Override to build (and index) against another tree, e.g.
#   make clangd KDIR=/path/to/arm64/headers
KDIR ?= /lib/modules/$(shell uname -r)/build

kernel:
	$(MAKE) -C kernel KDIR=$(KDIR)

user:
	$(MAKE) -C user

tags:
	ctags -R .

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -b -q -i cscope.files

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

# clangd compile database, one per tree, so clangd resolves symbols as an LSP
# alongside ctags/cscope. The kernel DB is read from the module's Kbuild .cmd
# files (the module is built first); the user DB is captured with bear. Both are
# specific to this machine and KDIR (absolute paths), so they are git-ignored;
# regenerate after changing KDIR. Needs python3 and bear.
clangd: compile_commands.json
compile_commands.json: kernel
	python3 $(KDIR)/scripts/clang-tools/gen_compile_commands.py -d kernel -o kernel/compile_commands.json
	printf '%s\n' "$$PW_INJECT_HDR_ENTRIES" | python3 -
	$(MAKE) -C user clean
	bear --output user/compile_commands.json -- $(MAKE) -C user all selftest

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	rm -f tags cscope.out cscope.in.out cscope.po.out cscope.files
	rm -f kernel/compile_commands.json user/compile_commands.json
