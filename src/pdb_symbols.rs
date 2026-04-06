use pdb2::{FallibleIterator, RawString};

use std::collections::{btree_map, BTreeMap};

use crate::utils::{leak, ToUsize};
use crate::Env;

#[derive(Default)]
pub struct PdbSymbols {
    pub functions: BTreeMap<usize, Vec<RawString<'static>>>,
    pub strings: BTreeMap<usize, (RawString<'static>, Vec<u8>)>,
    pub statics: BTreeMap<usize, RawString<'static>>,
}

impl PdbSymbols {
    pub fn parse<S>(env: &Env, pdb: &mut pdb2::PDB<'static, S>) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self::default();

        this.iterate_symbol_table(env)?;
        this.iterate_modules(env, pdb)?;

        Ok(this)
    }

    fn iterate_symbol_table(&mut self, env: &Env) -> anyhow::Result<()> {
        // Data symbols partially repeat Public symbols, but they also have unique symbols.
        //
        // Whenever available we would prefer Public symbols, since those are mangled and contain
        // type information.
        //
        // But we also want unique symbols.
        let mut static_data_symbols = vec![];

        let mut symbols = env.symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol {
                    function,
                    offset,
                    name,
                    ..
                })) if function => {
                    assert_eq!(offset.section, env.text.id);

                    let symbol_rva = env.text.rva + offset.offset.to_usize();

                    self.functions.entry(symbol_rva).or_default().push(name);
                }

                Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }))
                    if offset.section == env.rdata.id && name.as_bytes().starts_with(b"??_C@_") =>
                {
                    let symbol_rva = env.rdata.rva + offset.offset.to_usize();

                    let msvc_demangler::Type::ConstantString(string) =
                        msvc_demangler::parse(&name.to_string())?.symbol_type
                    else {
                        continue;
                    };

                    let old_symbol = self.strings.insert(symbol_rva, (name, string));
                    assert_eq!(old_symbol, None, "Constant symbols cannot repeat");
                }

                Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }))
                    if offset.section == env.data.id =>
                {
                    let symbol_rva = env.data.rva + offset.offset.to_usize();

                    let old_symbol = self.statics.insert(symbol_rva, name);
                    assert_eq!(old_symbol, None, "Static symbols cannot repeat");
                }

                // @TODO
                // Ignored for now.
                // There are not that many symbols and the ones with types are either U64 or F80.
                Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, .. }))
                    if offset.section == env.rdata.id => {}

                // in public they are mangled
                // in data all symbols are not mangled, yes
                Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. }))
                    if offset.section == env.data.id =>
                {
                    let symbol_rva = env.data.rva + offset.offset.to_usize();

                    static_data_symbols.push((symbol_rva, name));
                }
                _ => {}
            }
        }

        for (symbol_rva, name) in static_data_symbols {
            match self.statics.entry(symbol_rva) {
                btree_map::Entry::Vacant(entry) => _ = entry.insert(name),
                btree_map::Entry::Occupied(_) => (),
            }
        }

        Ok(())
    }

    fn iterate_modules<S>(
        &mut self,

        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,
    ) -> anyhow::Result<()>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut modules = env.dbi.modules()?;

        while let Some(module) = modules.next()? {
            let Some(module_info) = pdb.module_info(&module)? else {
                continue;
            };
            let module_info = leak(module_info);

            let mut iter = module_info.symbols()?;

            while let Some(symbol) = iter.next()? {
                match symbol.parse() {
                    //
                    // functions
                    //
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => self.add_function_symbol(env, name, offset, len),

                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        name, offset, len, ..
                    })) => self.add_function_symbol(env, name, offset, u32::from(len)),

                    //
                    // statics
                    //
                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. }))
                        if offset.section == env.data.id =>
                    {
                        let offset = offset.offset.to_usize();

                        match self.statics.entry(offset) {
                            btree_map::Entry::Occupied(_) => (),
                            btree_map::Entry::Vacant(entry) => {
                                entry.insert(name);
                            }
                        }
                    }

                    //
                    // constants
                    //
                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, .. }))
                        if offset.section == env.rdata.id =>
                    {
                        // TODO
                        // println!("module_data_symbol   {}", name);
                    }

                    Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })) => {
                        unreachable!()
                    }

                    _ => (),
                };
            }
        }

        Ok(())
    }

    fn add_function_symbol(
        &mut self,
        env: &Env,

        name: RawString<'static>,
        offset: pdb2::PdbInternalSectionOffset,
        size: u32,
    ) {
        let symbol_rva = env.text.rva + offset.offset.to_usize();

        let fun_offset_in_text = offset.offset.to_usize();
        let fun_body = &env.text.data[fun_offset_in_text..fun_offset_in_text + size.to_usize()];

        #[rustfmt::skip]
        const COMMON_FUNCTION_RENAMES: &[(&[u8], &[u8])] = &[
            (b"empty_stub", &[0xC3]),
            (b"identity",   &[0x8B, 0x44, 0x24, 0x04, 0xC3]),
            (b"vec_begin",  &[0x8B, 0x0, 0xC3]),
            (b"vec_size",   &[0x8B, 0x41, 0x04, 0x2B, 0x01, 0xC1, 0xF8, 0x02, 0xC3]),
        ];

        let fun_rename = COMMON_FUNCTION_RENAMES
            .iter()
            .find(|(_, code)| *code == fun_body)
            .map(|(name, _)| (*name).into());

        match self.functions.entry(symbol_rva) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(vec![fun_rename.unwrap_or(name)]);
            }
            btree_map::Entry::Occupied(mut entry) => match fun_rename {
                Some(fun_rename) => *entry.get_mut() = vec![fun_rename],
                None => (),
            },
        }
    }
}
