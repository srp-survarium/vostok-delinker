# Data manifest: design notes

The [data manifest](../README.md#data-manifest) is an optional, reviewed input
that supplies allocation facts a PDB alone cannot prove. This note records the
intent behind it; the [manifest format and fields](../README.md#manifest-format)
live in the README, and the `scope` column has its own deep-dive in
[scope.md](scope.md).

## Coverage is best-effort

The manifest is incremental. A global the manifest does not yet cover is not a
problem to solve: Vostok keeps its default fallback and materializes a private
per-TU copy of the referenced bytes instead of a shared external. That is
intended, not a defect — the manifest exists so a reconstruction project can
start matching functions in objdiff with whatever data it has reviewed so far,
and coverage grows over time. Only reviewed definitions are promoted to shared
external references and given a precise scope.
