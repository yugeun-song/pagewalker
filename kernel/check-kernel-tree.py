#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
import argparse
import glob
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

SYMVERS = re.compile(r"0x[0-9a-f]{8}\t\S+\t\S+\t\S+")
TARGETS = ("vmlinux", "scripts/mod/empty.o")
ENV = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MAKELEVEL", "MFLAGS")}


def fail(tree, why):
    print(f"{tree} is not a usable kernel tree: {why}")
    sys.exit(1)


def read(path, limit=1 << 20):
    try:
        with open(path, errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def run(*argv):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV,
                              cwd=tempfile.gettempdir())
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def elf(path):
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF" or head[4] not in (1, 2) or head[5] not in (1, 2):
        return None
    machine = struct.unpack("<H" if head[5] == 1 else ">H", head[18:20])[0]
    return "%d-%s-%d" % (32 * head[4], "le" if head[5] == 1 else "be", machine)


def machine(path):
    m = re.search(r"Machine:\s+(.+)", run("readelf", "-h", path) or "")
    return m.group(1).strip() if m else "an unknown machine"


def settings(text):
    return {k: v.strip('"') for k, v in re.findall(r"^(CONFIG_\w+)=(.*)$", text or "", re.M)}


def kernelversion(tree, src, minimum):
    head = read(os.path.join(src, "Makefile"), 4096) or ""
    keys = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION) =[ \t]*(\S*)[ \t]*$", head, re.M))
    nums = [keys.get(k, "") for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL")]
    if not all(n.isdigit() for n in nums):
        fail(tree, "its Makefile does not define the kernel's VERSION, PATCHLEVEL and SUBLEVEL")
    found = "%s.%s.%s%s" % (*nums, keys.get("EXTRAVERSION", ""))
    if (int(nums[0]), int(nums[1])) < minimum:
        fail(tree, "kernel %s is older than the minimum version %d.%d" % ((found,) + minimum))
    return found


def srcarch(src, arch):
    top = read(os.path.join(src, "Makefile")) or ""
    alias = dict(re.findall(r"^ifeq \(\$\(ARCH\),(\w+)\)\s*\n\s*SRCARCH\s*:=\s*(\w+)", top, re.M))
    return alias.get(arch, arch)


def subarch(src):
    text = (read(os.path.join(src, "scripts/subarch.include")) or "").replace("\\\n", " ")
    m = re.search(r"^SUBARCH := \$\(shell (.+)\)\s*$", text, re.M)
    return run("sh", "-c", m.group(1).replace("$$", "$")) if m else None


def reference(tree):
    present = [p for p in TARGETS if os.path.exists(os.path.join(tree, p))]
    kinds = {p: elf(os.path.join(tree, p)) for p in present}
    broken = [p for p, k in kinds.items() if k is None]
    if broken:
        fail(tree, f"{' and '.join(broken)} is not an ELF file")
    if len(set(kinds.values())) > 1:
        fail(tree, f"{' and '.join(present)} were built for different targets")
    return next(iter(kinds.values()), "none")


def symbols(tree):
    for name, kind in (("Module.symvers", "module"), ("vmlinux.symvers", "vmlinux")):
        path = os.path.join(tree, name)
        if os.path.exists(path):
            if not SYMVERS.match(read(path, 4096) or ""):
                fail(tree, f"{name} is not a symbol version list")
            return kind
    return "none"


def prepared(tree, src, found):
    release = (read(os.path.join(tree, "include/config/kernel.release")) or "").strip()
    if not release.startswith(found):
        fail(tree, f"include/config/kernel.release holds {release or 'nothing'}, the source is {found}")
    conf = settings(read(os.path.join(tree, "include/config/auto.conf")))
    if conf.get("CONFIG_MODULES") != "y":
        fail(tree, "its configuration does not enable CONFIG_MODULES")
    if "#define CONFIG_MODULES 1" not in (read(os.path.join(tree, "include/generated/autoconf.h")) or ""):
        fail(tree, "include/generated/autoconf.h does not enable CONFIG_MODULES")
    for tool in ("scripts/basic/fixdep", "scripts/mod/modpost"):
        path = os.path.join(tree, tool)
        if not (os.access(path, os.X_OK) and elf(path)):
            fail(tree, f"{tool} is not a built program")
    arches = sorted(p.split(os.sep)[-3] for p in glob.glob(os.path.join(tree, "arch/*/include/generated")))
    if len(arches) != 1:
        fail(tree, f"it has generated headers for {len(arches)} architectures instead of one")
    read_by_kconfig = set(re.findall(r"^\s*arch/([^/\s]+)/Kconfig",
                                     read(os.path.join(tree, "include/config/auto.conf.cmd")) or "", re.M))
    if read_by_kconfig and arches[0] not in read_by_kconfig:
        fail(tree, f"arch/{arches[0]} is generated, but kconfig read arch/{min(read_by_kconfig)}")
    for header in ("include/linux/module.h", "include/linux/kconfig.h"):
        if not os.path.isfile(os.path.join(src, header)):
            fail(tree, f"{header} is missing")
    return ["kind=prepared", f"release={release}", f"symvers={symbols(tree)}"], conf, arches[0]


def configured(tree, found, want):
    text = read(os.path.join(tree, ".config")) or ""
    head = re.search(r"^# Linux/(\S+) (\S+) Kernel Configuration$", text, re.M)
    if head and head.group(2) != found:
        fail(tree, f".config was made for {head.group(2)}, the source is {found}")
    if not head and not want:
        fail(tree, ".config does not say which ARCH it was made for; pass ARCH=")
    conf = settings(text)
    if conf.get("CONFIG_MODULES") != "y":
        fail(tree, "its .config does not enable CONFIG_MODULES")
    return ["kind=configured", "symvers=none"], conf, head.group(1) if head else want


def toolchain(tree, src, conf, arch, given):
    if any(given.values()):
        return {k: v for k, v in given.items() if v}, []
    if conf.get("CONFIG_CC_IS_CLANG") == "y":
        major = int(conf.get("CONFIG_CLANG_VERSION") or 0) // 10000
        tools = ("clang", "ld.lld", "llvm-ar", "llvm-nm", "llvm-objcopy", "llvm-objdump",
                 "llvm-readelf", "llvm-strip")
        if major and all(shutil.which(f"{t}-{major}") for t in tools):
            return {"llvm": f"-{major}"}, []
        if all(shutil.which(t) for t in tools):
            return {"llvm": "1"}, []
        fail(tree, "it was built with clang, and the LLVM tools kbuild needs are not installed")
    name = (conf.get("CONFIG_CC_VERSION_TEXT") or "gcc").split()[0]
    m = re.fullmatch(r"(.*?)gcc(-[\d.]+)?", name)
    if not m:
        fail(tree, f"it was built with {name}, which is neither gcc nor clang")
    prefix = m.group(1)
    if m.group(2) and shutil.which(name):
        return {"cross": prefix, "cc": name}, []
    if shutil.which(prefix + "gcc"):
        return {"cross": prefix}, [f"{name}:{prefix}gcc"] if m.group(2) else []
    if prefix and arch == subarch(src) and shutil.which("gcc"):
        return {}, [f"{name}:gcc"]
    fail(tree, f"it was built with {name}, and neither it nor {prefix}gcc is installed")


def tool_versions(src, conf, tc):
    suffix = tc["llvm"] if tc.get("llvm", "").startswith("-") else ""
    cc = tc.get("cc") or (f"clang{suffix}" if tc.get("llvm") else tc.get("cross", "") + "gcc")
    ld = f"ld.lld{suffix}" if tc.get("llvm") else tc.get("cross", "") + "ld"
    family = "CONFIG_CLANG_VERSION" if conf.get("CONFIG_CC_IS_CLANG") == "y" else "CONFIG_GCC_VERSION"
    linker = "CONFIG_LLD_VERSION" if conf.get("CONFIG_LD_IS_LLD") == "y" else "CONFIG_LD_VERSION"
    checks = [("cc", "cc-version.sh", cc, family), ("ld", "ld-version.sh", ld, linker)]
    if (conf.get("CONFIG_PAHOLE_VERSION") or "0") != "0":
        checks.append(("pahole", "pahole-version.sh", "pahole", "CONFIG_PAHOLE_VERSION"))
    if conf.get("CONFIG_RUST") == "y":
        checks.append(("rustc", "rustc-version.sh", "rustc", "CONFIG_RUSTC_VERSION"))
    differs = []
    for name, script, tool, key in checks:
        out = run("sh", os.path.join(src, "scripts", script), tool)
        host = out.split()[-1] if out else "none"
        if host != conf.get(key):
            differs.append(f"{name}:{conf.get(key) or 'none'}>{host}")
    return differs


def check(opts):
    tree = os.path.realpath(opts.tree)
    if not os.path.isdir(tree):
        fail(tree, "no such directory")
    src = os.path.join(tree, "source") if os.path.isdir(os.path.join(tree, "source")) else tree
    found = kernelversion(tree, src, tuple(map(int, opts.min_version.split("."))))
    if not all(os.path.isfile(os.path.join(src, "scripts", f)) for f in ("Kbuild.include", "Makefile.build")):
        fail(tree, "it lacks kbuild (scripts/Kbuild.include, scripts/Makefile.build)")
    if os.path.exists(os.path.join(tree, "include/config/kernel.release")):
        info, conf, arch = prepared(tree, src, found)
    elif os.path.exists(os.path.join(tree, ".config")):
        info, conf, arch = configured(tree, found, opts.arch)
    else:
        fail(tree, "it is kernel source that was never configured; configure it in place or with O=")
    base = srcarch(src, arch)
    if opts.arch and srcarch(src, opts.arch) != base:
        fail(tree, f"it is configured for {arch}, but ARCH={opts.arch}")
    if not os.path.isfile(os.path.join(src, "arch", base, "Makefile")):
        fail(tree, f"arch/{base}/Makefile is missing")
    ref = reference(tree)
    if opts.release and f"release={opts.release}" not in info:
        fail(tree, f"it was built as {info[1]}, not release={opts.release}")
    if opts.elf not in ("", "none", ref):
        fail(tree, f"its vmlinux is {machine(os.path.join(tree, 'vmlinux'))}, not the original's target")
    given = {"cross": opts.cross, "llvm": opts.llvm, "cc": opts.cc}
    tc, fallback = toolchain(tree, src, conf, base, given)
    differs = tool_versions(src, conf, tc)
    digest = hashlib.sha1(tree.encode() + b"\0" + (read(os.path.join(tree, ".config")) or "").encode())
    info += [f"version={found}", f"arch={opts.arch or arch}", f"srcarch={base}", f"src={src}",
             f"id={found}-{base}-{digest.hexdigest()[:8]}", f"elf={ref}"]
    if all(os.path.isfile(os.path.join(src, d, "Makefile")) for d in ("init", "kernel")):
        info.append("sources=1")
    if src != tree and not os.path.exists(os.path.join(src, ".config")):
        info.append("clean=1")
    info += [f"{k}={v}" for k, v in tc.items()]
    info += [f"fallback={','.join(fallback)}"] if fallback else []
    info += [f"tools={','.join(differs)}"] if differs else []
    print(" ".join(info))


def check_elf(opts):
    kdir = os.path.realpath(opts.kdir)
    ref = reference(kdir)
    if ref == "none":
        print(f"{opts.file}: {kdir} has no vmlinux or scripts/mod/empty.o to compare against")
        return
    got = elf(opts.file)
    if got != ref:
        target = next(os.path.join(kdir, p) for p in TARGETS if os.path.exists(os.path.join(kdir, p)))
        print(f"{opts.file} is built for {machine(opts.file)} ({got}), but {kdir} targets "
              f"{machine(target)} ({ref})")
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--min-version", required=True)
    for flag in ("--arch", "--cross", "--llvm", "--cc", "--release", "--elf"):
        c.add_argument(flag, default="")
    c.add_argument("tree")
    e = sub.add_parser("elf")
    e.add_argument("kdir")
    e.add_argument("file")
    opts = ap.parse_args()
    check(opts) if opts.cmd == "check" else check_elf(opts)


if __name__ == "__main__":
    main()
