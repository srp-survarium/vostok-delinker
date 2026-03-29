0. TODO: We can parse MSVC object files with object crate.

1. Parse executable with Capstone and pdb crates
2. For each function:
  1. Find an .object file in which this function will be stored or create it in a map (or some other data structure).
  2. For example, for 'survarium::game_core::initialize()' the object file should be at 'survarium/game_core'.
      Note that parsing this properly is a bit hard, but we don't need to be 100% exact.
  3. For each instruction in a function:
      1. If instruction refers to a constant (we still need to figure out a way to find those),
          write it into a .rdata with name 'fn_name__offset', so that we could match it between target and base
          and add it as a symbol (it will always be a new symbol)
      2. If instruction has a non-local jump (into another function), check if we already have such a symbol,
          if don't add it
      3. If instruction has a local jump (into the same function), we need to write it with offset from the beginning of the function.
      4. If instruction has an unknown jump, we need to write zero jump there.
      5. If instruction refers to a static (idk?, possibly something to take from debug symbols).
      6. Then build function as a vec and write it into object file (somehow, still don't know how)
  4. Register function in a symbol table.
3. Write each symbol file into its corresponding .obj file on the filesystem.
