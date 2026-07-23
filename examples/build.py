#!/usr/bin/env python3
"""Build and delink one Vostok example.

For the example directory given (default: the current directory), this:

  1. compiles the reference object the compiler itself emits for the TU,
  2. links an .exe + .pdb (the linked image Vostok consumes),
  3. runs `vostok-delinker` once per configured variant, generating any data or
     reloc manifest a variant needs, and
  4. reports, per variant, how the delinked object compares to the reference.

The toolchain is MSVC. On Windows it is invoked as plain `cl` / `link` (run this
from a Visual Studio developer prompt). On Linux it is MSVC under Wine: set
MSVC_DIR (the VC root holding VC/bin/cl.exe) and WINEPREFIX, exactly as the
reconstruction projects do. `vostok-delinker`, `llvm-pdbutil`, and `llvm-objdump`
must be on PATH (the delinker is also looked up at ../../target/release).

    python3 build.py [example-dir]
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

IS_WINDOWS = os.name == "nt"


def run(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def run_compiler(cmd, cwd):
    """Run cl/link, capturing output to a file rather than a pipe.

    cl spawns the persistent mspdbsrv daemon, which inherits the child's stdout
    handles and never closes them; capturing via a pipe would hang forever
    waiting for EOF. A regular file fd does not have that problem.
    """
    with tempfile.TemporaryFile(mode="w+", errors="replace") as log:
        p = subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=log, stderr=subprocess.STDOUT)
        log.seek(0)
        return p.returncode, log.read()


def die(msg):
    print(f"[build] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def tool(name, extra=None):
    found = shutil.which(name)
    if found:
        return found
    for cand in extra or []:
        if Path(cand).exists():
            return str(cand)
    die(f"{name} not found on PATH")


class Toolchain:
    """`cl` / `link` and Windows-path translation, native or via Wine."""

    def __init__(self):
        if IS_WINDOWS:
            self.cl = ["cl"]
            return
        msvc = os.environ.get("MSVC_DIR")
        if not msvc:
            die("MSVC_DIR is unset -- point it at the VC root that holds cl.exe")
        # cl.exe lives at a version-dependent subpath (VC/bin, bin, VC98/Bin, ...)
        # and its case varies (cl.exe vs CL.EXE), so match case-insensitively.
        def find_cl(dirs):
            for d in dirs:
                for p in (Path(msvc) / d).glob("*"):
                    if p.name.lower() == "cl.exe":
                        return p
            return None
        cl_exe = find_cl(["VC/bin", "bin", "VC98/Bin"]) or next(
            (p for p in Path(msvc).rglob("*") if p.name.lower() == "cl.exe"), None)
        if cl_exe is None:
            die(f"cl.exe not found under {msvc}")
        if not os.environ.get("WINEPREFIX"):
            die("WINEPREFIX is unset")
        os.environ.setdefault("WINEDEBUG", "fixme-all,err-all")
        self.cl = ["wine", str(cl_exe)]

    def winpath(self, p: Path) -> str:
        p = Path(p).resolve()
        if IS_WINDOWS:
            return str(p)
        out = run(["winepath", "-w", str(p)])
        return out.stdout.strip()

    def compile_object(self, src: Path, out_obj: Path):
        # /c /Z7: compile only, debug info in the object -- the reference object.
        # Run inside the output dir so cl's scratch (vc90.pdb) stays out of the
        # source tree; the source is passed as an absolute path.
        _, log = run_compiler(self.cl + ["/nologo", "/c", "/Z7",
                              "/Fo" + self.winpath(out_obj), self.winpath(src)],
                              cwd=out_obj.parent)
        if not out_obj.exists():
            die("reference compile failed:\n" + log)

    def link_image(self, src: Path, out_exe: Path, stripped: bool):
        # /Zi builds exe + pdb; /FIXED (stripped) drops the .reloc directory,
        # /FIXED:NO keeps it. Run inside the output dir (see compile_object).
        fixed = "/FIXED" if stripped else "/FIXED:NO"
        _, log = run_compiler(self.cl + ["/nologo", "/Zi",
                              "/Fe" + self.winpath(out_exe),
                              "/Fo" + self.winpath(out_exe.with_suffix(".obj")),
                              self.winpath(src), "/link", fixed], cwd=out_exe.parent)
        pdb = out_exe.with_suffix(".pdb")
        if not out_exe.exists() or not pdb.exists():
            die("link failed:\n" + log)
        return pdb


def section_vas(pdb: Path):
    r = run([tool("llvm-pdbutil"), "dump", "-section-headers", str(pdb)])
    vas, name = [], None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.endswith(" name"):
            name = line[: -len(" name")]
        elif line.endswith(" virtual address") and name is not None:
            vas.append(int(line.split()[0], 16))
            name = None
    return vas


def symbol_rva(pdb: Path, name: str) -> int:
    """RVA of a public symbol (matched as `_<name>`, MSVC's C decoration)."""
    vas = section_vas(pdb)
    r = run([tool("llvm-pdbutil"), "dump", "-publics", str(pdb)])
    want = f"`_{name}`"
    lines = r.stdout.splitlines()
    for i, line in enumerate(lines):
        if want in line:
            for follow in lines[i + 1: i + 3]:
                if "addr =" in follow:
                    # llvm-pdbutil prints "SEG:OFFSET" in decimal.
                    seg, off = follow.split("addr =")[1].strip().split(":")
                    return vas[int(seg) - 1] + int(off)
    die(f"symbol {name} not found in {pdb.name} publics")


def write_data_manifest(path: Path, owner: str, spec, rva: int):
    path.write_text(
        "object\trva\tsize\tstorage\talignment\tsection_offset\tscope\n"
        f"{owner}\t{rva:#x}\t{spec['size']:#x}\t{spec['storage']}\t"
        f"{spec['alignment']:#x}\t-\t{spec['scope']}\n"
    )


def find_dir32_sites(exe: Path, target_rva: int):
    """RVAs of 4-byte fields holding the target symbol's linked address -- the
    same analysis a project would run to review its relocation sites."""
    b = exe.read_bytes()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    coff = pe + 4
    num_sec, opt_size = struct.unpack_from("<HH", b, coff + 2)[0], \
        struct.unpack_from("<H", b, coff + 16)[0]
    image_base = struct.unpack_from("<I", b, coff + 20 + 28)[0]  # PE32 optional hdr
    needle = struct.pack("<I", image_base + target_rva)
    sites, sec = [], coff + 20 + opt_size
    for i in range(num_sec):
        off = sec + i * 40
        name = b[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vaddr, rawsize, rawptr = struct.unpack_from("<III", b, off + 12)
        if name not in (".text", ".rdata", ".data"):
            continue
        seg = b[rawptr:rawptr + rawsize]
        pos = seg.find(needle)
        while pos != -1:
            sites.append(vaddr + pos)
            pos = seg.find(needle, pos + 1)
    return sites


def write_reloc_manifest(path: Path, sites):
    rows = "".join(f"{s:#x}\tdir32\n" for s in sorted(set(sites)))
    path.write_text("site_rva\tkind\n" + rows)


def objdump(obj: Path, *args):
    return run([tool("llvm-objdump"), *args, str(obj)]).stdout


def section_size(obj: Path, name: str) -> int:
    for line in objdump(obj, "--section-headers").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == name:
            return int(parts[2], 16)
    return 0


def report(kind, ref: Path, got: Path, cfg):
    if kind == "functions":
        fns = lambda o: sorted(
            l.split("<")[1].split(">")[0]
            for l in objdump(o, "-d").splitlines() if ">:" in l)
        print(f"    reference functions: {fns(ref)}")
        print(f"    delinked  functions: {fns(got)}  <- same set")
    elif kind == "data_symbol_size":
        full = cfg.get("expect_full", 0)
        r, g = section_size(ref, ".rdata"), section_size(got, ".rdata")
        print(f"    reference .rdata = {r} bytes (holds the full {full}-byte table)")
        print(f"    delinked  .rdata = {g} bytes"
              + (f"  <- fragment, not the full {full}" if g < full
                 else f"  <- full table recovered"))
    elif kind == "relocations":
        rel = lambda o: [l.split(None, 2)[-1].strip()
                         for l in objdump(o, "-r").splitlines()
                         if "dir32" in l.lower()]
        print(f"    reference relocations: {rel(ref) or 'none'}")
        print(f"    delinked  relocations: {rel(got) or 'none'}"
              + ("  <- recovered" if rel(got) else "  <- absolute ref lost"))


def main():
    ex_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    cfg = json.loads((ex_dir / "config.json").read_text())
    tc = Toolchain()
    build = ex_dir / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir()

    src = ex_dir / cfg["source"]
    ref_obj = build / (src.stem + ".ref.obj")
    exe = build / (src.stem + ".exe")
    print(f"== {ex_dir.name}: {cfg['source']} ==")
    tc.compile_object(src, ref_obj)
    pdb = tc.link_image(src, exe, stripped=cfg["link"] == "fixed")
    print(f"  compiled reference {ref_obj.name}; linked {exe.name} + {pdb.name}"
          f" ({'stripped, no .reloc' if cfg['link']=='fixed' else 'with .reloc'})")

    # The PDB records the source under its own directory; engine-path strips that
    # prefix so the emitted object is named after the TU (e.g. basic.cpp.obj).
    engine = tc.winpath(src.parent) + ("\\" if not IS_WINDOWS else os.sep)
    delinker = tool("vostok-delinker",
                    [ex_dir.parents[1] / "target/release/vostok-delinker"])

    for v in cfg["variants"]:
        name = v["name"]
        out = build / f"delink-{name}"
        args = list(v.get("delink_args", []))
        generated = []  # (kind, path) manifests this variant produces and passes in
        if "data_manifest" in v:
            spec = v["data_manifest"]
            man = build / f"{name}.data-manifest.tsv"
            owner = cfg["unit_object"][:-4] if cfg["unit_object"].endswith(".obj") \
                else cfg["unit_object"]
            write_data_manifest(man, owner, spec, symbol_rva(pdb, spec["symbol"]))
            args += ["--data-manifest", str(man)]
            generated.append(("data manifest", man))
        if "reloc_manifest" in v:
            man = build / f"{name}.reloc-manifest.tsv"
            target = v["reloc_manifest"]["target_symbol"]
            sites = find_dir32_sites(exe, symbol_rva(pdb, target))
            write_reloc_manifest(man, sites)
            args += ["--reloc-manifest", str(man)]
            generated.append(("reloc manifest", man))

        print(f"\n  -- variant: {name} --")
        for kind, path in generated:
            print(f"    generated {kind} ({path.name}):")
            for line in path.read_text().splitlines():
                print(f"        {line}")
        r = run([str(delinker), "--pdb-path", str(pdb), "--exe-path", str(exe),
                 "--output-path", str(out), "--engine-path", engine, *args])
        if r.returncode != 0:
            first = (r.stderr.strip().splitlines() or ["<no output>"])[0]
            print(f"    delinker exited {r.returncode}: {first}")
            if v.get("expect_error"):
                print("    (expected -- this is the case the recovery input fixes)")
            continue
        got = out / cfg["unit_object"]
        if not got.exists():
            print(f"    delinked, but {cfg['unit_object']} not found in output")
            continue
        report(cfg["report"]["kind"], ref_obj, got, cfg["report"])


if __name__ == "__main__":
    main()
