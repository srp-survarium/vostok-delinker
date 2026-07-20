# Vostok Delinker

Vostok reconstructs per-translation-unit COFF object files from a linked PE
executable and a matching PDB. The executable supplies the linked bytes and PE
base relocations retained in its data directory, when present. The PDB supplies
the symbol and module topology used to split those bytes into objects.

## Synthetic PDB

Vostok expects a PDB that describes the executable being delinked. An original
PDB is not always available: a shipped executable may be stripped, may contain
only an older embedded debug format, or may have no surviving project PDB.

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

## Incremental-link trampolines

An incremental linker may redirect calls, jumps, and stored function addresses
through linker-created trampolines. CodeView represents these with
`S_TRAMPOLINE` records containing the exact trampoline and target offsets.
Vostok validates every incremental trampoline record against the corresponding
five-byte `JMP rel32` in the PE, requires an exact PDB procedure at its target,
and then reconstructs both relative and absolute references against that target
procedure. The linker-generated entry is not emitted as an object function.

Named `S_THUNK32` records remain ordinary object code. A synthetic PDB should
therefore describe incremental-link entries with `S_TRAMPOLINE`, rather than as
procedures or named thunks. Vostok does not infer a trampoline table by scanning
for address-looking jump instructions.

## PE base relocation input

Vostok locates retained base relocations through
`IMAGE_DIRECTORY_ENTRY_BASERELOC`, then reads exactly its RVA and size from one
raw-backed PE section. The section name is irrelevant; `.reloc` is conventional
but not required.

When the directory is absent, Vostok distinguishes an image carrying
`IMAGE_FILE_RELOCS_STRIPPED` from an image with no directory and no stripped
flag. For a `Stripped` image, Vostok can recover an absolute code relocation only
when a decoded x86 instruction has a four-byte operand whose linked value is the
exact address of a known PDB function, data symbol, string, or import slot. It
does not scan arbitrary address-sized words, and it does not treat a nearby PDB
address as a target. Relocation aliases, data-manifest ownership, and strict
manifest coverage retain their normal precedence. An `Absent` image receives no
such recovery because it does not provide evidence that relocations were
stripped.

PDB module Data records in `.text` delimit inline data within a procedure. A
CodeView type supplies the extent when its size is available; otherwise the
extent ends at the next `.text` Data record or at the exact PDB procedure end.
Instruction decoding skips those extents and resumes in any code that follows.
For a `Stripped` image, Vostok recovers aligned four-byte fields in those extents
only when their linked values point to one unambiguous, exact PDB text symbol or
to the exact containing-procedure entry. Nearby interior addresses and ambiguous
aliases are not inferred. Module Label records and `.text` Data symbols are
kept within their PDB module and emitted with their original names and local or
global scope; folded procedures at one RVA do not exchange local labels. MSVC
compiler symbols named `$L...` retain COFF label storage rather than becoming
data symbols merely because CodeView represents their inline-data extent with a
Data record.

## Import address table

Vostok recovers absolute references to imported functions and data without a
project manifest. It locates the import address table from the PE data directory,
so the table may use the conventional `.idata` section or be merged into a
differently named section. An exact PDB symbol at the referenced IAT slot supplies
the undefined COFF symbol name, such as `__imp__Function@4`; the linked slot
address is replaced with a zero addend and an absolute relocation.

Recovery requires a PE `HIGHLOW` base-relocation entry for the reference site.
When such an entry targets the IAT, the supplied PDB must name that exact slot;
Vostok reports an error instead of guessing a missing symbol identity. IAT
references are separate from reviewed data definitions and are unaffected by
`--strict`.

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
- whether its COFF symbol has external or compilation-local scope.

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
  --data-manifest build/data-manifest.tsv \
  --data-section-manifest build/data-sections.tsv
```

Add `--strict` to require every retained or recovered absolute relocation whose
target is in `.data` or `.rdata` to be covered by a manifest definition.
Function targets continue to use PDB procedure symbols. `--strict` requires
`--data-manifest` and reports both the relocation-site RVA and uncovered target
RVA on failure.

### Manifest format

The current format is a byte-oriented, tab-separated file. Empty lines and
lines beginning with `#` are ignored. The first non-comment line must be this
exact ASCII header:

```text
object	rva	size	storage	alignment	section_ordinal	section_offset	scope
```

Vostok parses the complete byte input with a `nom` grammar for LF/CRLF line
boundaries and the exact eight-field row shape. It then applies semantic checks
for paths, numbers, storage, extents, uniqueness, and overlap.

Each subsequent line defines one complete allocation:

| Field | Meaning |
| --- | --- |
| `object` | UTF-8 relative output object path. `/` is normalized to `\`; absolute paths and `.` or `..` components are rejected. |
| `rva` | Allocation start relative to the PE image base, in decimal or `0x` hexadecimal notation. A compatible PDB data symbol must begin at this exact RVA; that existing symbol supplies the identity. |
| `size` | Complete allocation extent in bytes, in decimal or `0x` hexadecimal notation. |
| `storage` | `data`, `rdata`, or `bss`. |
| `alignment` | Required byte alignment; it must be a non-zero power of two. |
| `section_ordinal` | One-based ordinal from the data section manifest, or `-` to use the object's default storage section. A numeric ordinal requires a numeric section offset. |
| `section_offset` | Expected byte offset in the selected candidate section, or `-` when that topology has not been reviewed. Numeric offsets control emission order and are verified against the emitted COFF object. |
| `scope` | `external` for a linkage-visible COFF symbol or `local` for a compilation-local symbol. |

Start RVAs must be unique. Extents must be non-zero, non-overlapping,
non-overflowing, and contained in the corresponding linked PE section. Storage
must agree with the PDB symbol's PE section. A `bss` definition cannot contain a
PE base relocation.

Example:

```text
object	rva	size	storage	alignment	section_ordinal	section_offset	scope
vendor\zlib\infutil.c	0x00123450	0x44	data	0x4	3	0x20	local
```

This says that the existing PDB data symbol at RVA `0x00123450` is a 68-byte
initialized definition, aligned to four bytes, compilation-local, located at
offset `0x20` in candidate section 3, and owned by
`vendor\zlib\infutil.c.obj`. The manifest does not supply or invent its name.

### Data section manifest

The optional data section manifest records the candidate COFF section table
independently of symbol identity. Its first non-comment line must be this exact
header:

```text
object	ordinal	name	rva	size	alignment	characteristics	checksum	comdat_selection	associative_ordinal	storage
```

Each object's ordinals must be unique, contiguous, and start at one. The fields
have these meanings:

| Field | Meaning |
| --- | --- |
| `object` | Relative output object path, normalized by the same rules as the data manifest. |
| `ordinal` | One-based position in the original COFF section table. |
| `name` | Original one-to-eight-byte COFF section name. |
| `rva` | Start RVA of an affine linked data range, or `-` when definitions must be copied independently into candidate offsets. |
| `size` | Original section extent in bytes. |
| `alignment` | Original non-zero, power-of-two section alignment. |
| `characteristics` | Complete COFF section characteristics in decimal or `0x` hexadecimal notation. |
| `checksum` | Exact checksum from the COFF section-definition auxiliary record. |
| `comdat_selection` | COFF selection value: `0` none, `1` no duplicates, `2` any, `3` same size, `4` exact match, `5` associative, `6` largest, or `7` newest. |
| `associative_ordinal` | Leader section ordinal for selection `5`, otherwise `-`. The leader must precede the associative section. |
| `storage` | `data`, `rdata`, or `bss` for a data-bearing candidate section, otherwise `-`. `data` accepts `.data` and linker-sorted `.CRT$*` subsections. An RVA requires storage, while storage may be present without an affine RVA. |

The manifest owns section order, names, characteristics, alignment, linked data
ranges, and COMDAT relationships. The PDB still owns symbol names. Data-manifest
rows bind definitions to these sections by ordinal and offset; the section
manifest never creates or renames a definition.

When this manifest is supplied, its section table is exact: Vostok does not add
unused `.data`, `.rdata`, or `.text` sections that are absent from its rows. A
section needed by emitted content is created only when that content is actually
encountered. Without the manifest, Vostok synthesizes its default section set.
Exact-topology output replaces the object writer's generated section-definition
checksums only for manifest-declared sections, using each row's reviewed value.

Vostok materializes affine `.data`, `.rdata`, and `.bss` ranges directly from
the linked image. For a storage-assigned section without an affine RVA, it
creates the complete candidate extent, places every reviewed data-manifest
definition at its section offset, copies initialized payloads from each
definition's independent retail RVA, and retains zero-filled gaps and `.bss`.
Definition ranges in one candidate section may not overlap.

The implementation also emits non-associative data COMDAT groups. It preserves
the order, names, and characteristics of non-data rows as empty section records;
recovering their contents and associative groups requires additional reviewed
input.

Assigned data sections are checked before emission. Affine RVA placement must
satisfy the declared alignment; the numeric alignment must agree with the COFF
characteristics; storage must agree with the section name and initialized,
uninitialized, and writable flags; and COMDAT flags must agree with the
selection value. Placed ranges cannot overlap unless two different objects
describe the same foldable COMDAT range with identical topology. Every bound
definition must fit inside its selected section and agree with its section-local
RVA.

### What the manifest improves

For each row Vostok copies the complete `.data` or `.rdata` payload, or allocates
the complete `.bss` extent, in the named object. It defines the existing PDB
symbol at that location with the reviewed size, alignment, and scope and keeps
references from other objects external. Numeric candidate offsets order
definitions within each selected section and reject a layout that emits a
different offset. A reference to an interior address is represented as that PDB
symbol plus its in-place COFF addend.

Relocation sites are not invented by the manifest. Vostok starts from existing
PE `HIGHLOW` base-relocation entries or, for a `Stripped` image, from the
evidence-gated instruction operands described above. It resolves their data
targets through the manifest allocation ranges to existing PDB symbols and
serializes the recovered relationships as COFF relocations in the output
objects. The final COFF records must be emitted because linking consumed the
originals; a retained PE base-relocation entry preserves only its site and
linked target address.

When a candidate section has an assigned linked range, Vostok replays every PE
base relocation in that complete range. This includes relocation sites in
padding or in bytes not covered by an individual definition row, and repeats
the relocation topology for each compatible folded COMDAT copy.

Without a manifest row, Vostok may only materialize a small referenced fragment
in the referring function's object. In a tested VC4.2 example, a 1,024-byte
table was emitted as a four-byte fragment and matched its compiler definition at
`0.7782101%`. Supplying its single reviewed manifest row emitted all 1,024 bytes
in the owner object and matched the definition at `100.0%`.

The data manifest restores reviewed definitions and their position within each
emitted storage section. The data section manifest separately restores reviewed
same-name sections and COMDAT topology.

## Relocation alias manifest

An absolute relocation identifies its site and final linked target address, but
linking consumed the original COFF symbol/addend spelling. When multiple PDB
data symbols can describe that address, nearest-symbol selection may choose an
interior or anonymous symbol even though the source object used a different
existing owner symbol plus an addend.

The optional relocation alias manifest records reviewed spellings for data and
function references in PDB functions:

```sh
cargo run --release -- \
  --pdb-path build/game.pdb \
  --exe-path build/game.exe \
  --output-path build/delink \
  --engine-path 'c:\project\sources' \
  --reloc-alias-manifest build/reloc-aliases.tsv
```

Its first non-comment line must be this exact header:

```text
function_rva	target_rva	site_rva	owner	addend	occurrences
```

| Field | Meaning |
| --- | --- |
| `function_rva` | Exact start RVA of the PDB function containing the relocation sites. |
| `target_rva` | Exact linked RVA encoded at those retained PE relocation sites. |
| `site_rva` | Exact RVA of one four-byte relocation field, or `*` for every matching site not covered by an exact row. |
| `owner` | Existing PDB data symbol or function alias that the candidate COFF relocations should reference. |
| `addend` | Unsigned 32-bit COFF addend bits, including two's-complement encodings such as `0xfffffff8`. |
| `occurrences` | Exact number of matching relocation sites expected in that function. |

Example:

```text
function_rva	target_rva	site_rva	owner	addend	occurrences
0xd3910	0x134de0	*	?hSequence@@3PAPAU_SEQUENCE@@A	0	5
0xd3910	0x134de0	0xd3aa5	?pMIDIWrap@@3PAPAVMIDIWrap@@A	0xf0	1
```

Data aliases apply only to existing `HIGHLOW` relocation sites inside `.text`.
The owner must occur exactly once in the applicable PDB data-symbol table, and
`owner RVA + addend` must wrap to the declared target RVA. Function aliases
also apply to decoded external `call`, `jmp`, and conditional-branch targets,
and to exact absolute function references retained by `HIGHLOW`; their owner
must be one of the PDB aliases at the target RVA and their addend must be zero.
Every manifest row must be observed exactly `occurrences` times; a stale or
overly broad row stops the delink. An exact site row takes precedence over a
wildcard row with the same function and target and must declare one occurrence.
Its four-byte relocation field must lie entirely within the declared PDB
function's exact Procedure/Thunk extent. A Public-only function remains a valid
target name, but cannot own reviewed relocation sites without a known extent.
The manifest neither invents sites nor names.

Recovered external function references use the COFF derived-function type for
both relative branches and absolute function pointers. Data references remain
untyped COFF symbols.
