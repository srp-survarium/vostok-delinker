// 02-data-manifest: recover a whole data allocation, not just the fragment
// that is referenced.
//
// square_of() indexes kSquares. In the linked image the reference is a base
// relocation pointing at the start of the table; the table itself is just
// bytes with no size attached. Given only the exe + pdb, Vostok can prove the
// reference exists but not how large the allocation is -- so it materializes a
// small fragment (the referenced word) in this object.
//
// The data manifest supplies the reviewed allocation: owner object, start RVA,
// exact byte size, storage, alignment, and linkage. With it, Vostok emits the
// complete 256-byte table and the emitted object matches the compiler's.
//
// build.py delinks twice -- without and with --data-manifest -- and reports the
// emitted table size both times so the difference is visible.
//
// `extern "C"` only keeps the symbol name unmangled so the scripts can find it;
// it is not required by Vostok.
//
// build.py writes these into this example's build/ (generated, git-ignored):
//   table.ref.obj                    the compiler's object -- the comparison target
//   table.exe, table.pdb             the linked image + PDB Vostok consumes
//   with-manifest.data-manifest.tsv  the reviewed allocation, derived from the PDB
//                                    each run (the RVA is link-dependent, so it is
//                                    not a committed static file)
//   delink-without-manifest/, delink-with-manifest/   Vostok's output each way
// It then reports the emitted table size without the manifest (a 4-byte fragment)
// and with it (the full 256 bytes).

extern "C" const int kSquares[64] = {
    0,    1,    4,    9,    16,   25,   36,   49,
    64,   81,   100,  121,  144,  169,  196,  225,
    256,  289,  324,  361,  400,  441,  484,  529,
    576,  625,  676,  729,  784,  841,  900,  961,
    1024, 1089, 1156, 1225, 1296, 1369, 1444, 1521,
    1600, 1681, 1764, 1849, 1936, 2025, 2116, 2209,
    2304, 2401, 2500, 2601, 2704, 2809, 2916, 3025,
    3136, 3249, 3364, 3481, 3600, 3721, 3844, 3969,
};

int square_of(int i) {
    return kSquares[i & 0x3f];
}

int main() {
    return square_of(9);
}
