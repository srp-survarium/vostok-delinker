// 04-synthetic-pdb: delink an image that shipped with NO debug information.
//
// This is the workflow the reconstruction projects actually run (see the
// README's "Synthetic PDB" section): a retail game has no PDB, so the project
// synthesizes one from its own reverse-engineering knowledge -- function
// addresses, sizes, names, and translation-unit ownership -- and Vostok
// consumes the synthetic PDB exactly as it would a real one.
//
// The program is deliberately the same shape as 01-basic so the two runs can
// be compared: 01 gets everything from the compiler's own PDB; here the
// compiler contributes nothing but the linked bytes.
//
// Where the "reverse engineering" comes from in this example: the image is
// linked with a .map file, and synth_pdb.py treats the map as the project's
// knowledge base -- the same facts a real project recovers with analysis
// tooling. Stage 1 distills it into an explicit symbol INVENTORY
// (example.symbols.tsv: rva, size, name, kind, unit); stage 2 synthesizes the
// PDB from that inventory alone. A real project derives the same inventory
// from its own source annotations or analysis databases and can feed it in
// directly via --symbols. From the map:
//
//   - function RVAs: the `Publics by Value` rows for this TU's object;
//   - function sizes: the distance to the next .text symbol (real projects
//     refine these; the delta over-approximates by trailing padding);
//   - TU ownership: the map's object column, expressed in the PDB as per-
//     function line records pointing at `c:\proj\example.cpp`;
//   - the globals' RVAs: their data rows in the same map.
//
// build.py writes these into this example's build/ (generated, git-ignored):
//   example.ref.obj                the compiler's object -- the comparison target
//   example.exe, example.map      the release-linked image (NO pdb) + linker map
//   example.symbols.tsv           the distilled symbol inventory (stage 1)
//   example.synth.yaml/.synth.pdb the synthesized PDB and its YAML source
//   delink-synthetic-pdb/example.cpp.obj   Vostok's reconstruction
// It then reports that the delinked object carries the same functions as the
// reference, with every name supplied by the synthetic PDB.

// The image is linked /NODEFAULTLIB /ENTRY:main: no CRT, so every byte of the
// image belongs to this TU and the synthetic PDB's coverage is COMPLETE. That
// mirrors the real workflow's precondition -- the reconstruction projects name
// every symbol before delinking (Vostok resolves data relocations against the
// nearest named symbol, so unnamed regions poison the attribution).

extern "C" int g_scale = 7;         // .data  -> S_LDATA32 in the synthetic PDB
extern "C" const int k_bias = 3;    // .rdata -> S_LDATA32 in the synthetic PDB

int helper(int x) {
    return x * g_scale;
}

int compute(int x) {
    return helper(x) + k_bias;
}

int main() {
    return compute(13);
}
