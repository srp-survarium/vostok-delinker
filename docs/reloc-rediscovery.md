# Relocations without `.reloc`

See the README ("Relocations without a `.reloc` section") for the two recovery
inputs. This page details the reloc-manifest format and what a missed rediscovery
costs.

## Reloc manifest (`--reloc-manifest`)

An exact, reviewed list of the sites the `.reloc` directory would have held. It is
a byte-oriented TSV; blank lines and `#` comments are ignored, and the first
non-comment line is the header:

    site_rva	kind
    0x004a1077	dir32
    0x004a1120	dir32

- `site_rva` -- RVA of the 4-byte field holding a linked target address (decimal
  or `0x` hex). The delinker reads and classifies the target itself, so only the
  site is needed. Sites must be unique.
- `kind` -- `dir32` (absolute). Relative branches come from the decoder.

Manifest sites are authoritative; when `--rediscover-relocations-from-pdb` is also
passed, rediscovery fills only the sites the manifest omits. Extract the manifest
from a tool that already knows the real pointers/xrefs (Ghidra, IDA).

## A missed relocation

`--rediscover-relocations-from-pdb` is best-effort, so it misses some
relocations.


A missed site stays a raw absolute address in the emitted object, with no COFF
relocation. objdiff masks relocation fields, so where the base relocates against a
symbol the target's un-relocated literal shows through as a mismatch:

    base:    mov eax, [__table]     ; relocation -> __table
    target:  mov eax, [0x004a1234]  ; missed -> literal, mismatches

A miss costs that field's match, not the whole object.
