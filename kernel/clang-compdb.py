#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
import argparse
import glob
import json
import os
import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor

WITH_VALUE = {"-include", "-isystem", "-o", "-MF", "-x", "-idirafter", "-imacros"}
NO_PROBE = ("-I", "-D", "-U", "-Wp,")
DEPS = re.compile(r"^deps_\S+ := \\$")


def triple_of(args):
    name = os.path.basename(args[0])
    if name.endswith("-gcc"):
        return name[: -len("-gcc")]
    return next((a.split("=", 1)[1] for a in args if a.startswith("--target=")), None)


def candidates(args):
    skip = False
    for a in args[1:]:
        if skip:
            skip = False
        elif a in WITH_VALUE:
            skip = True
        elif a.startswith("-") and not a.startswith(NO_PROBE) and a not in ("-c", "-nostdinc"):
            yield a


def accepted(key):
    flag, triple = key
    argv = ["clang", "-fsyntax-only", "-x", "c", "-c", os.devnull,
            "-Werror=unknown-warning-option", "-Werror=ignored-optimization-argument"]
    if triple:
        argv.append(f"--target={triple}")
    return subprocess.run(argv + [flag], capture_output=True).returncode == 0


def source_of(entry):
    return os.path.realpath(os.path.join(entry["directory"], entry["file"]))


def dependencies(source, directory):
    stem = os.path.splitext(os.path.basename(source))[0]
    cmdfile = os.path.join(os.path.dirname(source), f".{stem}.o.cmd")
    found = []
    in_deps = False
    try:
        with open(cmdfile, errors="replace") as f:
            for line in f:
                if in_deps:
                    path = line.strip().rstrip("\\").strip()
                    if not path:
                        break
                    if not path.startswith("$("):
                        found.append(os.path.realpath(os.path.join(directory, path)))
                elif DEPS.match(line.rstrip("\n")):
                    in_deps = True
    except OSError:
        pass
    return found


def tracked(root, patterns):
    listed = subprocess.run(["git", "-C", root, "ls-files", "--", *patterns], capture_output=True, text=True)
    if listed.returncode == 0:
        return listed.stdout.split()
    suffixes = tuple(p.lstrip("*") for p in patterns)
    found = []
    for top, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        found += [os.path.relpath(os.path.join(top, n), root) for n in sorted(names)
                  if n.endswith(suffixes) and not n.endswith(".mod.c")]
    return found


def alias_of(tree, dirs):
    for link in sorted(p for d in dirs for p in glob.glob(os.path.join(os.path.expanduser(d), "*"))):
        if os.path.islink(link) and os.path.realpath(link) == tree:
            return link
    return None


def main():
    ap = argparse.ArgumentParser(description="Make a kbuild compile_commands.json fit clang tools.")
    ap.add_argument("--db", required=True, help="compile_commands.json written by kbuild, rewritten in place")
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--kdir", required=True, help="kernel build tree the database was built against")
    ap.add_argument("--profile", required=True, help="build profile, for the report")
    ap.add_argument("--headers", action="store_true",
                    help="add every repository header with the command of a unit that includes it")
    ap.add_argument("--cscope", help="write the repository sources and the kernel headers they include here")
    ap.add_argument("--link-dirs", default="", help="directories whose links may replace the kernel path")
    ap.add_argument("--map", action="append", default=[], help="OLD=NEW path to rewrite")
    ap.add_argument("--previous", help="the database this one replaces; report only when they differ")
    opts = ap.parse_args()
    root = os.path.realpath(opts.root)
    kdir = os.path.realpath(opts.kdir)

    db = json.load(open(opts.db))
    for entry in db:
        if "command" in entry:
            entry["arguments"] = shlex.split(entry.pop("command"))
    keys = {(flag, triple_of(e["arguments"])) for e in db for flag in candidates(e["arguments"])}
    with ThreadPoolExecutor(max_workers=len(os.sched_getaffinity(0))) as pool:
        verdicts = dict(zip(keys, pool.map(accepted, keys)))
    rejected = sorted({flag for (flag, _), ok in verdicts.items() if not ok})
    for entry in db:
        args = entry["arguments"]
        triple = triple_of(args)
        kept = [a for a in args[1:] if a != "-Qunused-arguments" and verdicts.get((a, triple), True)]
        entry["arguments"] = [args[0], "-Qunused-arguments"] + kept

    deps = {source_of(e): dependencies(source_of(e), e["directory"]) for e in db}
    added = 0
    if opts.headers:
        have = set(deps)
        units = sorted(db, key=source_of)
        for header in sorted(os.path.join(root, h) for h in tracked(root, ["*.h"])):
            unit = next((e for e in units if header in deps[source_of(e)]), None)
            if unit is None or header in have:
                continue
            source = source_of(unit)
            args = [header if os.path.realpath(os.path.join(unit["directory"], a)) == source else a
                    for a in unit["arguments"]]
            db.append({"directory": unit["directory"], "file": header, "arguments": args[:1] + ["-xc"] + args[1:]})
            added += 1

    replace = [m.split("=", 1) for m in opts.map]
    link = alias_of(kdir, opts.link_dirs.split())
    if link:
        replace.append([kdir, link])
    headers = sorted({d for found in deps.values() for d in found if not d.startswith(root + os.sep)})
    for old, new in replace:
        tree = re.compile(re.escape(old) + r"(?=/|$)")
        for entry in db:
            entry["directory"] = tree.sub(new, entry["directory"])
            entry["arguments"] = [tree.sub(new, a) for a in entry["arguments"]]
        headers = [tree.sub(new, h) for h in headers]

    text = json.dumps(db, indent=1) + "\n"
    with open(opts.db + ".tmp", "w") as f:
        f.write(text)
    os.replace(opts.db + ".tmp", opts.db)
    if opts.previous:
        try:
            with open(opts.previous) as f:
                unchanged = f.read() == text
            os.remove(opts.previous)
        except OSError:
            unchanged = False
        if unchanged:
            return
    via = f", kernel via {link}" if link else ""
    with_headers = f" ({added} headers)" if opts.headers else ""
    print(f"=> {os.path.relpath(opts.db)}: {len(db)} entries{with_headers} with the {opts.profile} flags "
          f"for {kdir}{via}, {len(rejected)} gcc-only flags dropped")
    if not opts.previous:
        for flag in rejected:
            print(f"  dropped {flag}")

    if opts.cscope:
        repo = tracked(root, ["*.c", "*.h"])
        with open(opts.cscope + ".tmp", "w") as f:
            f.write("\n".join(repo + headers) + "\n")
        os.replace(opts.cscope + ".tmp", opts.cscope)
        print(f"=> {os.path.relpath(opts.cscope)}: {len(repo)} repository files and {len(headers)} kernel headers")


if __name__ == "__main__":
    main()
