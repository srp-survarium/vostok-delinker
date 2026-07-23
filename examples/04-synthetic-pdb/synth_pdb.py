#!/usr/bin/env python3
"""synth_pdb.py - synthesize a PDB for an image that shipped without one.

A heavily simplified version of the synthesizers the reconstruction projects
run against their retail images. The flow is two explicit stages:

  1. KNOWLEDGE ACQUISITION -> build/<name>.symbols.tsv
     Here the linker .map supplies the facts (function RVAs from the publics,
     sizes by distance to the next .text symbol, TU ownership from the map's
     object column, data rows for globals). A real project derives the same
     inventory from its own source annotations or analysis databases and can
     feed it directly via --symbols, skipping the map stage entirely.

  2. SYNTHESIS: symbols.tsv -> PDB-YAML -> `llvm-pdbutil yaml2pdb` -> .pdb
     What Vostok needs from the PDB, and how the YAML supplies it:
       - a module whose records carry the names: one S_GPROC32 per function
         (segment:offset, size, display name) and one S_LDATA32 per datum;
       - translation-unit ownership, so the delinker knows which output object
         a function belongs to: per-function line records (!Lines) pointing at
         the owning source file under the --engine prefix;
       - segment indices matching the image's PE section table (1-based).
     One post-step remains: yaml2pdb leaves the DBI header's symbol-records
     stream as nil (0xFFFF), which the `pdb2` crate rejects, so that field is
     patched to point at an existing empty stream.

The inventory format is one row per symbol, RVAs in image terms:

    rva	size	name	kind	unit
    0x1000	0xf	?helper@@YAHH@Z	func	example.cpp
    0x3000	-	_g_scale	data	example.cpp

Sizes come from the classic map trick -- distance to the next .text symbol --
which over-approximates by the linker's inter-function padding; real projects
refine sizes from analysis, but for delinking whole functions the tail padding
is harmless. Data rows carry no size (S_LDATA32 needs only segment:offset).

Usage (build.py drives this):
    synth_pdb.py --exe <img.exe> --map <img.map> --out <synth.pdb> \
                 --object <unit.obj> --source <unit.cpp>
    synth_pdb.py --exe <img.exe> --symbols <symbols.tsv> --out <synth.pdb>
"""

import argparse
import hashlib
import re
import struct
import subprocess
from pathlib import Path

ENGINE_PREFIX = "c:\\proj\\"
INVENTORY_HEADER = "rva\tsize\tname\tkind\tunit"


def read_sections(exe: Path):
    """PE section table: [(name, seg_1based, base_rva, end_rva)]."""
    d = exe.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    num = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    secs = []
    for i in range(num):
        off = pe + 24 + opt + i * 40
        name = d[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr = struct.unpack_from("<II", d, off + 8)
        secs.append((name, i + 1, vaddr, vaddr + vsize))
    return secs


# --- stage 1: knowledge acquisition (map -> inventory rows) -----------------

def parse_map(map_path: Path, unit_obj: str):
    """All `Publics by Value` rows: [(rva, seg, name, is_func, is_ours)].

    A map row looks like (VC6 and later agree on the shape):
        0001:00000000  ?helper@@YAHH@Z  00401000 f  example.obj
    The trailing object column is what attributes a symbol to our TU.
    """
    base = None
    rows = []
    in_publics = False
    for line in map_path.read_text(errors="replace").splitlines():
        if "Preferred load address" in line:
            base = int(line.split()[-1], 16)
        if "Publics by Value" in line:
            in_publics = True
            continue
        if not in_publics:
            continue
        toks = line.split()
        if len(toks) < 4 or not re.fullmatch(r"[0-9a-fA-F]{4,}:[0-9a-fA-F]+", toks[0]):
            continue
        if base is None:
            raise SystemExit("[synth] no 'Preferred load address' before publics")
        seg = int(toks[0].split(":")[0], 16)
        rva = int(toks[2], 16) - base
        is_func = "f" in toks[3:-1]
        rows.append((rva, seg, toks[1], is_func, toks[-1].lower() == unit_obj.lower()))
    if not rows:
        raise SystemExit(f"[synth] no publics parsed from {map_path}")
    return rows


def inventory_from_map(map_path: Path, exe: Path, unit_obj: str, unit_src: str):
    """Inventory rows [(rva, size_or_None, name, kind, unit)] for our TU."""
    secs = read_sections(exe)
    text_seg, text_end = next((seg, e) for n, seg, _b, e in secs if n == ".text")
    rows = parse_map(map_path, unit_obj)
    text_rvas = sorted(r for r, seg, _n, _f, _o in rows if seg == text_seg)
    inventory = []
    for rva, seg, name, is_func, ours in sorted(rows):
        if not ours:
            continue
        if is_func and seg == text_seg:
            nxt = next((r for r in text_rvas if r > rva), text_end)
            inventory.append((rva, nxt - rva, name, "func", unit_src))
        else:
            inventory.append((rva, None, name, "data", unit_src))
    return inventory


def write_inventory(path: Path, inventory):
    lines = [INVENTORY_HEADER]
    for rva, size, name, kind, unit in inventory:
        lines.append(f"{rva:#x}\t{'-' if size is None else f'{size:#x}'}"
                     f"\t{name}\t{kind}\t{unit}")
    path.write_text("\n".join(lines) + "\n")


def read_inventory(path: Path):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != INVENTORY_HEADER:
        raise SystemExit(f"[synth] bad inventory header in {path}")
    inventory = []
    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        rva, size, name, kind, unit = line.split("\t")
        inventory.append((int(rva, 0), None if size == "-" else int(size, 0),
                          name, kind, unit))
    return inventory


# --- stage 2: synthesis (inventory -> YAML -> pdb) --------------------------

def yaml_for(source_win: str, funcs, data, text_seg):
    """PDB-YAML: one module, per-function !Lines for TU ownership, then the
    module symbol records. funcs: [(rva_off, size, name)] (offset within the
    text segment); data: [(seg, off, name)]."""
    md5 = hashlib.md5(source_win.encode()).hexdigest().upper()
    out = [
        "MSF:",
        "  SuperBlock:",
        "    BlockSize:       4096",
        "    FreeBlockMap:    2",
        "    NumBlocks:       0",
        "    NumDirectoryBytes: 0",
        "    Unknown1:        0",
        "    BlockMapAddr:    0",
        "PdbStream:",
        "  Age:             1",
        "  Guid:            '{00000000-0000-0000-0000-000000000000}'",
        "  Signature:       0",
        "  Features:        [ VC140 ]",
        "  Version:         VC70",
        "DbiStream:",
        "  VerHeader:       V70",
        "  Age:             1",
        "  BuildNumber:     0",
        "  PdbDllVersion:   0",
        "  PdbDllRbld:      0",
        "  Flags:           0",
        "  MachineType:     x86",
        "  Modules:",
        f"    - Module:          '{source_win[:-4]}'",
        f"      ObjFile:         '{source_win[:-4]}'",
        "      SourceFiles:",
        f"        - '{source_win}'",
        "      Subsections:",
        "        - !FileChecksums",
        "          Checksums:",
        f"            - FileName:        '{source_win}'",
        "              Kind:            MD5",
        f"              Checksum:        {md5}",
    ]
    for off, size, _name in funcs:
        out += [
            "        - !Lines",
            f"          CodeSize:        {size}",
            "          Flags:           [  ]",
            f"          RelocOffset:     {off}",
            f"          RelocSegment:    {text_seg}",
            "          Blocks:",
            f"            - FileName:        '{source_win}'",
            "              Lines:",
            "                - Offset:          0",
            "                  LineStart:       1",
            "                  EndDelta:        0",
            "                  IsStatement:     true",
            "              Columns:         []",
        ]
    out += ["      Modi:", "        Records:"]
    for off, size, name in funcs:
        out += [
            "          - Kind:            S_GPROC32",
            "            ProcSym:",
            f"              CodeSize:        {size}",
            "              DbgStart:        0",
            "              DbgEnd:          0",
            "              FunctionType:    0",
            f"              Offset:          {off}",
            f"              Segment:         {text_seg}",
            "              Flags:           [  ]",
            f"              DisplayName:     '{name}'",
            "          - Kind:            S_END",
            "            ScopeEndSym:     {}",
        ]
    for seg, off, name in data:
        out += [
            "          - Kind:            S_LDATA32",
            "            DataSym:",
            "              Type:            0",
            f"              Offset:          {off}",
            f"              Segment:         {seg}",
            f"              DisplayName:     '{name}'",
        ]
    out += ["StringTable:", f"  - '{source_win}'", ""]
    return "\n".join(out)


def patch_symbol_records_stream(pdb: Path):
    """Point DBIHeader.symbol_records_stream at an existing EMPTY stream.

    yaml2pdb writes 0xFFFF (nil) there and `pdb2` refuses to open the global
    symbol table of such a PDB. Walk the MSF directory for the DBI stream
    (fixed index 3) and patch the u16 at offset 0x14 in its first block.
    """
    dump = subprocess.run(["llvm-pdbutil", "dump", "--streams", str(pdb)],
                          capture_output=True, text=True, check=True).stdout
    empty = next((int(m.group(1)) for line in dump.splitlines()
                  if (m := re.search(r"Stream\s+(\d+)\s+\(\s*0 bytes\)", line))),
                 None)
    if empty is None:
        raise SystemExit("[synth] no empty stream to point symbol records at")
    d = bytearray(pdb.read_bytes())
    bs = struct.unpack_from("<I", d, 32)[0]
    num_dir_bytes = struct.unpack_from("<I", d, 44)[0]
    blk_map_addr = struct.unpack_from("<I", d, 52)[0]
    ndir = (num_dir_bytes + bs - 1) // bs
    dir_blocks = [struct.unpack_from("<I", d, blk_map_addr * bs + 4 * i)[0]
                  for i in range(ndir)]
    directory = b"".join(d[b * bs:b * bs + bs] for b in dir_blocks)[:num_dir_bytes]
    nstreams = struct.unpack_from("<I", directory, 0)[0]
    sizes = [struct.unpack_from("<i", directory, 4 + 4 * i)[0]
             for i in range(nstreams)]
    pos = 4 + 4 * nstreams
    blocks = []
    for s in sizes:
        nb = 0 if s < 0 else (s + bs - 1) // bs
        blocks.append([struct.unpack_from("<I", directory, pos + 4 * j)[0]
                       for j in range(nb)])
        pos += 4 * nb
    DBI = 3
    struct.pack_into("<H", d, blocks[DBI][0] * bs + 0x14, empty)
    pdb.write_bytes(d)


def synthesize(inventory, exe: Path, out: Path):
    secs = read_sections(exe)
    by_seg = {seg: (name, base) for name, seg, base, _e in secs}
    text_seg, text_base = next((seg, b) for n, seg, b, _e in secs if n == ".text")

    units = sorted({unit for *_rest, unit in inventory})
    if len(units) != 1:
        raise SystemExit("[synth] this simplified synthesizer emits one module; "
                         "a multi-TU inventory needs one !Lines file per unit")

    def seg_of(rva):
        return next((seg for _n, seg, base, end in secs if base <= rva < end),
                    None)

    funcs, data = [], []
    for rva, size, name, kind, _unit in inventory:
        if kind == "func":
            funcs.append((rva - text_base, size, name))
        else:
            seg = seg_of(rva)
            if seg is None:
                raise SystemExit(f"[synth] data symbol outside sections: {name}")
            data.append((seg, rva - by_seg[seg][1], name))

    source_win = ENGINE_PREFIX + units[0]
    yaml = out.with_suffix(".yaml")
    yaml.write_text(yaml_for(source_win, funcs, data, text_seg))
    if out.exists():
        out.unlink()
    subprocess.run(["llvm-pdbutil", "yaml2pdb", "-pdb", str(out), str(yaml)],
                   check=True)
    patch_symbol_records_stream(out)
    print(f"[synth] {len(funcs)} functions + {len(data)} data symbols "
          f"-> {out.name} (module {source_win})")


def main():
    ap = argparse.ArgumentParser(description="Synthesize a PDB from a symbol inventory.")
    ap.add_argument("--exe", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--map", type=Path, dest="mapfile",
                     help="linker map to derive the inventory from")
    src.add_argument("--symbols", type=Path,
                     help="project-supplied inventory TSV (skips the map stage)")
    ap.add_argument("--object",
                    help="with --map: this TU's object name (e.g. example.obj)")
    ap.add_argument("--source",
                    help="with --map: this TU's source file name (e.g. example.cpp)")
    args = ap.parse_args()

    if args.symbols:
        tsv = args.symbols
    else:
        if not (args.object and args.source):
            ap.error("--map requires --object and --source")
        tsv = args.out.parent / (args.out.stem.removesuffix(".synth") + ".symbols.tsv")
        write_inventory(tsv, inventory_from_map(args.mapfile, args.exe,
                                                args.object, args.source))
    inventory = read_inventory(tsv)
    print(f"[synth] inventory {tsv.name}:")
    for line in tsv.read_text().splitlines():
        print(f"[synth]     {line}")
    synthesize(inventory, args.exe, args.out)


if __name__ == "__main__":
    main()
