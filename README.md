# Vostok Delinker

Vostok reconstructs per-translation-unit COFF object files from a linked PE
executable and a matching PDB. The executable supplies the linked bytes and PE
base relocations. The PDB supplies the symbol and module topology used to split
those bytes into objects.

## Synthetic PDB

Vostok expects a PDB that describes the executable being delinked. An original
PDB is not always available: a shipped executable may be stripped, may contain
only an older embedded debug format, or may have no surviving project PDB.

**PDB format.** Vostok reads the modern PDB 7.0 container introduced with Visual
Studio .NET 2002 (MSVC 13.0). PDBs from that toolset onward are supported
(verified through Visual Studio 2008); PDBs produced by Visual C++ 6.0 and
earlier (MSVC 4.2, 5.0, 6.0) use the legacy format and are rejected with
`ancient DBI header` or `UnexpectedEof`. A synthetic PDB is always written in the
modern format, so this limit applies only when delinking against an original
compiler PDB.

A reconstruction project can generate a synthetic PDB from its recovered symbol
inventory. This solves four immediate problems for the delinker:

- **Symbol identity:** function and data addresses regain their exact recovered
  names instead of being emitted as anonymous addresses.
- **Function boundaries:** procedure records provide the RVA and byte extent
  needed to extract individual functions from the linked `.text` section.
- **Translation-unit attribution:** module, source-file, and line records tell
  Vostok which output object should receive each function.
- **Symbolic relocations:** named function and data targets let Vostok turn
  linked addresses back into COFF relocations against symbols.

Conceptually, a project supplies these records:

```text
procedure: RVA + size + name + module/source file
data:      RVA + name
```

The exact recovery process belongs to the reconstruction project. It may use
surviving debug records, trusted library objects, executable analysis, or
reviewed source identities. Vostok does not generate the synthetic PDB and does
not treat invented symbol-name encodings as metadata.

```text
recovered symbol and unit records ──> synthetic PDB ──┐
                                                       ├──> Vostok ──> COFF objects
linked executable ─────────────────────────────────────┘
```

Invoke Vostok with the resulting PDB exactly as with an original PDB:

```sh
cargo run --release -- \
  --pdb-path build/game.synthetic.pdb \
  --exe-path build/game.exe \
  --output-path build/delink \
  --engine-path 'c:\project\sources'
```

Run `vostok-delinker --help` for the complete option list.

## Relocations without a `.reloc` section

A fixed-base or stripped executable (`IMAGE_FILE_RELOCS_STRIPPED`) carries no
base-relocation directory. Vostok still recovers relative branches from the
instruction decoder; the absolute relocations the `.reloc` directory would have
listed come from one of two recovery inputs, which may be combined:

- `--reloc-manifest` -- a reviewed TSV of exact `site_rva`/`kind` rows (see
  [docs/reloc-rediscovery.md](docs/reloc-rediscovery.md)). Authoritative.
- `--rediscover-relocations-from-pdb` -- the best-effort scan described below;
  when combined with a manifest it fills only the sites the manifest omits.

A present `.reloc` directory is already complete, so passing either recovery
input alongside it is rejected; an image that lacks `.reloc` and is given neither
is a hard error, not a silent partial delink. The scan itself locates 4-byte
fields in `.text`/`.rdata`/`.data` that hold the address of a known PDB symbol
and reconstructs a relocation for each.

Most relocations point *inside* a symbol, not at its start (`&table[i]`,
`&s.field`, a jump-table entry). Because PDB data symbols often lack sizes,
`--rediscovery-interior-bound` (default 32) stands in for the symbol's extent: a
scanned address is trusted when it lands in the half-open window `[S, S + bound)`
of the nearest known symbol start `S`.

```text
     S (known symbol start)                 S + bound
     |                                      |
     |========== trusted window ===========|  . . . not trusted
     |   accept a target in [ S, S+bound ) |
     |                                      |
     S+0            S+0x10                  S+bound          far off
     exact start    interior pointer        just past        no nearby
     -> ACCEPT      -> ACCEPT               -> REJECT         symbol
                                                              -> REJECT
```

A larger bound catches deeper interior pointers (more recall) but trusts more
coincidental in-range words (lower precision); `0` accepts exact starts only.

This is a best-effort bootstrap. Measured against the real `.reloc` on games that
still have one, the default captures roughly 78-86% of relocations at 98-99%
precision (about 1-2% of the emitted relocations are false). A project past
bootstrapping supplies those sites via `--reloc-manifest` instead of relying on
the scan.

A relocation the scan misses surfaces in objdiff as a raw absolute address; see
[docs/reloc-rediscovery.md](docs/reloc-rediscovery.md).

## Data manifest

The data manifest is an independent, optional input. It is useful with both an
original PDB and a synthetic PDB.

A PDB data symbol identifies a name and address, but it does not reliably give
Vostok every property of the original COFF allocation. Even a real project PDB
may have incomplete types, optimized-away private definitions, or insufficient
information to reproduce the original object layout. Vostok therefore cannot
always determine:

- the complete byte extent of a standalone data definition;
- whether the original allocation was `.data`, `.rdata`, or `.bss`;
- its original alignment;
- the translation unit that should own the complete definition;
- its position in the candidate object's storage section;
- whether the definition has external or internal linkage — a non-`static`
  global versus a `static` (or anonymous-namespace) one.

A reconstruction project that has reviewed those facts supplies them with
`--data-manifest`. The PDB continues to provide symbol and module topology; the
manifest adds explicit allocation topology.

```text
linked executable ─────────────────────┐
original or synthetic PDB ─────────────┼──> Vostok ──> COFF objects
reviewed data allocations ─> manifest ─┘
```

Vostok does not generate the manifest. A project may derive it from original
source, trusted rebuilt vendor objects, debug types, or other reviewed evidence.
This makes it directly applicable to statically linked vendor code such as zlib,
where pristine source and a matching compiler object can prove allocation size,
storage, alignment, and owner object.

```sh
cargo run --release -- \
  --pdb-path build/game.pdb \
  --exe-path build/game.exe \
  --output-path build/delink \
  --engine-path 'c:\project\sources' \
  --data-manifest build/data-manifest.tsv
```

Add `--strict` to require every PE base relocation whose target is in `.data`
or `.rdata` to be covered by a manifest definition. Function targets continue
to use PDB procedure symbols. `--strict` requires `--data-manifest` and reports
both the relocation-site RVA and uncovered target RVA on failure.

### Manifest format

The current format is a byte-oriented, tab-separated file. Empty lines and
lines beginning with `#` are ignored. The first non-comment line must be this
exact ASCII header:

```text
object	rva	size	storage	alignment	section_offset	scope
```

Vostok parses the complete byte input with a `nom` grammar for LF/CRLF line
boundaries and the exact seven-field row shape. It then applies semantic checks
for paths, numbers, storage, extents, uniqueness, and overlap.

Each subsequent line defines one complete allocation:

| Field | Meaning |
| --- | --- |
| `object` | UTF-8 relative output object path. `/` is normalized to `\`; absolute paths and `.` or `..` components are rejected. |
| `rva` | Allocation start relative to the PE image base, in decimal or `0x` hexadecimal notation. A compatible PDB data symbol must begin at this exact RVA; that existing symbol supplies the identity. |
| `size` | Complete allocation extent in bytes, in decimal or `0x` hexadecimal notation. |
| `storage` | `data`, `rdata`, or `bss`. |
| `alignment` | Required byte alignment; it must be a non-zero power of two. |
| `section_offset` | Expected byte offset in the candidate object's storage section, or `-` when that topology has not been reviewed. Numeric offsets control emission order and are verified against the emitted COFF object. |
| `scope` | The definition's source-level linkage: `local` for a `static` (internal linkage) definition, `external` for a non-`static` global (external linkage). A global is `external` even when only its own TU uses it — scope follows the declaration, not usage. See [docs/scope.md](docs/scope.md). |

Start RVAs must be unique. Extents must be non-zero, non-overlapping,
non-overflowing, and contained in the corresponding linked PE section. Storage
must agree with the PDB symbol's PE section. A `bss` definition cannot contain a
PE base relocation.

Example:

```text
object	rva	size	storage	alignment	section_offset	scope
vendor\zlib\infutil.c	0x00123450	0x44	data	0x4	0x20	local
```

This says that the existing PDB data symbol at RVA `0x00123450` is a 68-byte
initialized definition, aligned to four bytes, compilation-local, located at
offset `0x20` in its candidate `.data` section, and owned by
`vendor\zlib\infutil.c.obj`. The manifest does not supply or invent its name.

### What the manifest improves

For each row Vostok copies the complete `.data` or `.rdata` payload, or allocates
the complete `.bss` extent, in the named object. It defines the existing PDB
symbol at that location with the reviewed size, alignment, and scope and keeps
references from other objects external. Numeric candidate offsets order definitions
within each object's storage section and reject a layout that emits a different
offset. A reference to an interior address is represented as that PDB symbol plus
its in-place COFF addend.

Relocation sites are not invented by the manifest. Vostok starts from existing
PE `HIGHLOW` base-relocation entries, resolves their data targets through the
manifest allocation ranges to existing PDB symbols, and serializes the recovered
relationships as COFF relocations in the output objects. The final COFF records
must be emitted because linking consumed the originals; the PE retains only the
base-relocation sites and linked target addresses.

Without a manifest row, Vostok may only materialize a small referenced fragment
in the referring function's object. In a tested VC4.2 example, a 1,024-byte
table was emitted as a four-byte fragment and matched its compiler definition at
`0.7782101%`. Supplying its single reviewed manifest row emitted all 1,024 bytes
in the owner object and matched the definition at `100.0%`.

The manifest restores reviewed definitions and their order within each emitted
storage section. It does not by itself reconstruct multiple same-name original
sections or COMDAT grouping. Those are separate pieces of COFF topology.
