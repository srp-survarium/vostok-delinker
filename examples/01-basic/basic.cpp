// 01-basic: split a linked image back into one translation unit.
//
// No manifests -- just an .exe and its .pdb. Vostok extracts this TU's
// functions into basic.obj and recovers the call from compute() to helper()
// as a COFF relocation against the helper symbol, instead of the linked
// relative displacement the image actually contains.
//
// This is the whole tool in miniature: PDB gives names, boundaries, and the
// owning translation unit; the linked bytes give the code; Vostok emits a COFF
// object an assembler/objdiff can read.
//
// build.py writes these into this example's build/ (generated, git-ignored):
//   basic.ref.obj                 the object the compiler itself emits -- the
//                                 reference the delinked object is compared to
//   basic.exe, basic.pdb          the linked image + PDB Vostok consumes
//   delink-default/basic.cpp.obj  Vostok's reconstructed object
// It then reports that the reconstruction carries the same functions as the
// reference.

int helper(int x) {
    return x * 3;
}

int compute(int x) {
    return helper(x) + 1;
}

int main() {
    return compute(13);
}
