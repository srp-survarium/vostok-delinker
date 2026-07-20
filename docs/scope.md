# Data definition scope

The `scope` column of the [data manifest](../README.md#data-manifest) records a
reviewed definition's **source-level linkage**. It is a property of how the
symbol was declared, and it fixes the storage class of the COFF symbol Vostok
emits for the definition.

| `scope`    | Source declaration                          | Linkage  | COFF symbol class          | `object` crate scope         |
| ---------- | ------------------------------------------- | -------- | -------------------------- | ---------------------------- |
| `external` | a non-`static` global                       | external | `IMAGE_SYM_CLASS_EXTERNAL`  | `SymbolScope::Linkage`       |
| `local`    | a `static` / anonymous-namespace definition | internal | `IMAGE_SYM_CLASS_STATIC`    | `SymbolScope::Compilation`   |

## Scope follows the declaration, not usage

Scope is **not** a reachability property. A symbol is not "local until another
translation unit references it, then external":

- A non-`static` global has **external** linkage and stays `external` **even if
  only its own TU ever uses it**. It is still a globally visible symbol; nothing
  about being unreferenced makes it local.
- A `static` (or anonymous-namespace) definition has **internal** linkage and is
  `local`. It is invisible to other objects *by construction* — no other TU can
  name it.

## Why it matters

Vostok delinks the retail executable into per-object COFF "target" files and
objdiff pairs them against the freshly compiled "base" objects. cl.exe emits a
`static` as a compilation-local symbol and a plain global as an external one, so
the target object must carry the same class or objdiff sees a scope mismatch and
the two symbols do not line up.

The distinction also governs how a **cross-object reference** resolves. When a
function references a global that another object owns, Vostok emits an undefined
`EXTERNAL` relocation against that name; the linker resolves it to the owning
object's definition. That resolution only works when the owning definition is
`external`. A `local` definition cannot satisfy a reference from another object,
which is the invariant the manifest must respect: mark a definition `local` only
when it is genuinely single-TU; anything referenced across TUs must be
`external`. (When several objects each legitimately own the *same* external
definition, the linker folds the copies — see the folded-COMDAT handling in the
data manifest.)

Vostok does not infer scope. The reconstruction project decides each definition's
linkage when it generates the manifest; Vostok only honors the reviewed value.
Coverage of the manifest itself is best-effort — see
[data-manifest.md](data-manifest.md#coverage-is-best-effort).
