// 03-reloc-recovery: recover absolute relocations for a stripped image.
//
// Linked with /FIXED, this image has IMAGE_FILE_RELOCS_STRIPPED and no .reloc
// directory -- the linker consumed every base-relocation site. read_value()
// still loads from the absolute address of g_value (a DIR32 site inside the
// function's code). Vostok cannot know that operand is a relocation site rather
// than an ordinary constant, so by default the reference surfaces with no
// relocation at all.
//
// Two recovery inputs restore it (build.py demonstrates both):
//
//   --rediscover-relocations-from-pdb
//       Scans .text/.rdata/.data for a 4-byte word whose value equals the
//       address of a known PDB symbol. g_value is a PDB symbol, so the operand
//       is recognized as pointing at it and a relocation is rebuilt. This is how
//       the PDB helps: its symbol addresses turn an anonymous constant back into
//       a symbolic reference.
//
//   --reloc-manifest
//       A reviewed list of exact site RVAs. build.py derives the site by the
//       same kind of analysis a project would (locating the operand that holds
//       g_value's address) and feeds it as an authoritative site.
//
// `extern "C"` only keeps the name unmangled for the scripts.
//
// build.py writes these into this example's build/ (generated, git-ignored):
//   absref.ref.obj                     the compiler's object -- the comparison target
//   absref.exe, absref.pdb             the linked /FIXED (stripped) image + PDB
//   reloc-manifest.reloc-manifest.tsv  the reviewed site RVA, located by scanning
//                                      the image each run (also link-dependent, so
//                                      not a committed static file)
//   delink-no-recovery/, delink-rediscover-from-pdb/, delink-reloc-manifest/
//                                      Vostok's output for each recovery variant
// It then reports the relocations recovered each way (none without recovery).

extern "C" int g_value = 123;

int read_value() {
    return g_value;
}

int main() {
    return read_value();
}
