# Examples

Each example is a tiny C++ translation unit that is compiled and linked with
MSVC, delinked by Vostok, and compared against the object the compiler itself
emitted. They exist to show, on the smallest possible input, what Vostok does by
default and what each optional manifest adds.

Every example is self-contained: a `.cpp`, a `config.json`, and (for the manifest
examples) the reviewed facts a project would supply. `build.py` drives the whole
cycle and prints the before/after so the effect of each input is visible.

## Running

```sh
python3 build.py 01-basic
python3 build.py 02-data-manifest
python3 build.py 03-reloc-recovery
```

`build.py` compiles the reference object, links the `.exe` + `.pdb`, runs
`vostok-delinker` once per configured variant (generating any manifest a variant
needs), and reports the comparison. Artifacts land in each example's `build/`
(git-ignored).

### Toolchain

The compiler is MSVC. `vostok-delinker`, `llvm-pdbutil`, and `llvm-objdump` must
be on `PATH` (the delinker is also looked up at `../target/release`).

- **Windows:** run from a Visual Studio developer prompt, where `cl` and `link`
  are on `PATH`.
- **Linux:** MSVC under Wine, exactly as the reconstruction projects use it. Set
  `MSVC_DIR` (the VC root that holds `cl.exe`) and `WINEPREFIX`, and `LIB` if the
  prefix does not already export it. `build.py` invokes `wine cl.exe` and
  translates paths with `winepath`.

### PDB format

The delink step needs a modern PDB. The compile and link steps work with any
MSVC (verified from VC4.2 through VS2008), but Vostok's PDB reader supports only
the newer format: a VS2008 (VC9) PDB reads correctly, while VC4.2 / VC5 / VC6
PDBs are rejected (`ancient DBI header`, `UnexpectedEof`). This is also why the
reconstruction projects feed Vostok a *synthetic* PDB rather than a period
compiler's own.

## The examples

### 01-basic -- the tool in miniature

Split a linked image back into one translation unit, with no manifests at all.
Vostok extracts the TU's functions and recovers the call between them as a COFF
relocation. The delinked object carries the same functions as the compiler's:

```
reference functions: ['?compute@@YAHH@Z', '?helper@@YAHH@Z', '_main']
delinked  functions: ['?compute@@YAHH@Z', '?helper@@YAHH@Z', '_main']  <- same set
```

### 02-data-manifest -- recover a whole allocation, not a fragment

A function indexes a 256-byte table. The linked image only carries a base
relocation to the table's start, with no size, so by default Vostok can only
materialize the referenced fragment. The data manifest supplies the reviewed
allocation (owner, RVA, size, storage, alignment, linkage) and the full table is
emitted. `build.py` generates the manifest from the compiled image and prints it,
then delinks with and without it:

```
generated data manifest (with-manifest.data-manifest.tsv):
    object     rva      size   storage  alignment  section_offset  scope
    table.cpp  0x17a60  0x100  rdata    0x4        -               external

without-manifest:  delinked .rdata = 4 bytes    <- fragment, not the full 256
with-manifest:     delinked .rdata = 256 bytes   <- full table recovered
```

The RVA is link-dependent, so the manifest cannot be a committed static file --
`build.py` derives it from the PDB (via `llvm-pdbutil`) each run.

### 03-reloc-recovery -- absolute relocations for a stripped image

Linked `/FIXED`, the image has no `.reloc` directory, so an absolute reference is
lost. Vostok refuses to guess and fails loudly; two inputs recover it:

```
no-recovery:          Error: image has no `.reloc` ... supply --reloc-manifest
                      and/or --rediscover-relocations-from-pdb
rediscover-from-pdb:  delinked relocations: ['_g_value']  <- recovered
reloc-manifest:       delinked relocations: ['_g_value']  <- recovered
```

For the `reloc-manifest` variant, `build.py` locates the site (the operand that
holds `g_value`'s address) by scanning the image -- the analysis a project would
review -- and prints the manifest it feeds in:

```
generated reloc manifest (reloc-manifest.reloc-manifest.tsv):
    site_rva  kind
    0x1024    dir32
```

`--rediscover-relocations-from-pdb` is the best-effort scan: it finds a word whose
value equals a known PDB symbol's address, which is how the PDB turns an anonymous
constant back into a symbolic reference. `--reloc-manifest` supplies the same
sites as authoritative, reviewed input.
