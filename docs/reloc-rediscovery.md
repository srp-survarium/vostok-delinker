# Relocation rediscovery

`--rediscover-relocations-from-pdb` (see the README, "Relocations without a
`.reloc` section") is best-effort, so it misses some relocations.

## A missed relocation

A missed site stays a raw absolute address in the emitted object, with no COFF
relocation. objdiff masks relocation fields, so where the base relocates against a
symbol the target's un-relocated literal shows through as a mismatch:

    base:    mov eax, [__table]     ; relocation -> __table
    target:  mov eax, [0x004a1234]  ; missed -> literal, mismatches

A miss costs that field's match, not the whole object.
