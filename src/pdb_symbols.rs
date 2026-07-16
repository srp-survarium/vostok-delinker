use pdb2::{FallibleIterator, RawString};

use std::collections::{BTreeMap, btree_map};

use crate::Env;
use crate::utils::{ToUsize, leak};

#[derive(Default)]
pub struct PdbSymbols {
    pub functions: BTreeMap<usize, Vec<RawString<'static>>>,
    pub strings: BTreeMap<usize, (RawString<'static>, Vec<u8>)>,

    pub constants: BTreeMap<usize, RawString<'static>>,
    pub statics: BTreeMap<usize, RawString<'static>>,
}

impl PdbSymbols {
    pub fn parse<S>(
        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,
        coalesce_common_functions: bool,
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self::default();

        this.iterate_symbol_table(env)?;
        this.iterate_modules(env, pdb, coalesce_common_functions)?;

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
        let mut constant_data_symbols = vec![];

        let mut symbols = env.symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            let symbol = symbol.parse()?;

            let (name, offset) = match &symbol {
                pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }) => (name, offset),
                pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. }) => (name, offset),
                _ => continue,
            };
            let name = *name;

            let symbol_rva = match () {
                () if offset.section == env.text.id => env.text.rva + offset.offset.to_usize(),
                () if offset.section == env.rdata.id => env.rdata.rva + offset.offset.to_usize(),
                () if offset.section == env.data.id => env.data.rva + offset.offset.to_usize(),
                _ => continue,
            };

            match symbol {
                // @NOTE: There are more symbols in `.text`, which are not functions.
                // Seem to be useless though:
                // 0x1cba96: __imp_load__CoInitialize@4
                // 0x19963d: __nosnan2
                pdb2::SymbolData::Public(pdb2::PublicSymbol { function, .. }) if function => {
                    assert_eq!(offset.section, env.text.id);

                    Self::push_function_name(self.functions.entry(symbol_rva).or_default(), name);
                }

                pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })
                    if offset.section == env.rdata.id && name.as_bytes().starts_with(b"??_C@_") =>
                {
                    let msvc_demangler::Type::ConstantString(string) =
                        msvc_demangler::parse(&name.to_string())?.symbol_type
                    else {
                        unreachable!()
                    };

                    let old_symbol = self.strings.insert(symbol_rva, (name, string));
                    assert_eq!(old_symbol, None, "Constant symbols cannot repeat");
                }

                pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })
                    if offset.section == env.rdata.id =>
                {
                    // @TODO: There can be multiple symbols for the same constant name.
                    // While it makes sense to keep all of them and find closest,
                    // for now we simply keep one.
                    let _old_symbol = self.constants.insert(symbol_rva, name);
                }

                pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })
                    if offset.section == env.data.id =>
                {
                    let old_symbol = self.statics.insert(symbol_rva, name);
                    assert_eq!(old_symbol, None, "Static symbols cannot repeat");
                }

                // Unmangled data symbols to cover missing spots.
                pdb2::SymbolData::Data(pdb2::DataSymbol { .. })
                    if offset.section == env.rdata.id =>
                {
                    constant_data_symbols.push((symbol_rva, name));
                }
                pdb2::SymbolData::Data(pdb2::DataSymbol { .. })
                    if offset.section == env.data.id =>
                {
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

        for (symbol_rva, name) in constant_data_symbols {
            match self.constants.entry(symbol_rva) {
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
        coalesce_common_functions: bool,
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
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => {
                        self.add_function_symbol(env, name, offset, len, coalesce_common_functions)
                    }
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        name, offset, len, ..
                    })) => self.add_function_symbol(
                        env,
                        name,
                        offset,
                        u32::from(len),
                        coalesce_common_functions,
                    ),

                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. })) => {
                        let symbol_rva = match () {
                            () if offset.section == env.rdata.id => {
                                env.rdata.rva + offset.offset.to_usize()
                            }
                            () if offset.section == env.data.id => {
                                env.data.rva + offset.offset.to_usize()
                            }
                            _ => continue,
                        };

                        match () {
                            () if offset.section == env.rdata.id => {
                                let _old_symbol = self.constants.insert(symbol_rva, name);
                            }
                            () if offset.section == env.data.id => {
                                // Prefer symbol names from modules.
                                // As those are closer to the original symbols.
                                // For comparison see: `survarium::damage_zone_cook::damage_zone_cook`.
                                let _old_symbol = self.statics.insert(symbol_rva, name);
                            }
                            _ => continue,
                        };
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
        coalesce_common_functions: bool,
    ) {
        let symbol_rva = env.text.rva + offset.offset.to_usize();

        let fun_offset_in_text = offset.offset.to_usize();
        let fun_body = &env.text.data[fun_offset_in_text..fun_offset_in_text + size.to_usize()];

        self.add_function_at_rva(symbol_rva, name, fun_body, coalesce_common_functions);
    }

    fn add_function_at_rva(
        &mut self,
        symbol_rva: usize,
        name: RawString<'static>,
        fun_body: &[u8],
        coalesce_common_functions: bool,
    ) {
        #[rustfmt::skip]
        const COMMON_FUNCTION_RENAMES: &[(&[u8], &[u8])] = &[
            (b"empty_stub", &[0xC3]),
            (b"identity",   &[0x8B, 0x44, 0x24, 0x04, 0xC3]),
            (b"vec_begin",  &[0x8B, 0x0, 0xC3]),
            (b"vec_size",   &[0x8B, 0x41, 0x04, 0x2B, 0x01, 0xC1, 0xF8, 0x02, 0xC3]),
        ];

        let fun_rename = if coalesce_common_functions {
            COMMON_FUNCTION_RENAMES
                .iter()
                .find(|(_, code)| *code == fun_body)
                .map(|(name, _)| (*name).into())
        } else {
            None
        };

        match self.functions.entry(symbol_rva) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(vec![fun_rename.unwrap_or(name)]);
            }
            btree_map::Entry::Occupied(mut entry) => match fun_rename {
                Some(fun_rename) => *entry.get_mut() = vec![fun_rename],
                None => Self::push_function_name(entry.get_mut(), name),
            },
        }
    }

    fn push_function_name(names: &mut Vec<RawString<'static>>, name: RawString<'static>) {
        if !names
            .iter()
            .any(|existing| existing.as_bytes() == name.as_bytes())
        {
            names.push(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON_FIXTURES: &[(&[u8], &[u8])] = &[
        (b"empty_stub", &[0xC3]),
        (b"identity", &[0x8B, 0x44, 0x24, 0x04, 0xC3]),
        (b"vec_begin", &[0x8B, 0x0, 0xC3]),
        (
            b"vec_size",
            &[0x8B, 0x41, 0x04, 0x2B, 0x01, 0xC1, 0xF8, 0x02, 0xC3],
        ),
    ];

    #[test]
    fn common_byte_patterns_keep_real_names_and_aliases_by_default() {
        for (index, (synthetic, body)) in COMMON_FIXTURES.iter().enumerate() {
            let mut symbols = PdbSymbols::default();
            let rva = 0x1000 + index;
            symbols.add_function_at_rva(rva, b"real_a".as_slice().into(), body, false);
            symbols.add_function_at_rva(rva, b"real_b".as_slice().into(), body, false);

            let names = &symbols.functions[&rva];
            assert_eq!(names.len(), 2);
            assert_eq!(names[0].as_bytes(), b"real_a");
            assert_eq!(names[1].as_bytes(), b"real_b");
            assert!(names.iter().all(|name| name.as_bytes() != *synthetic));
        }
    }

    #[test]
    fn legacy_opt_in_coalesces_all_common_byte_patterns() {
        for (index, (synthetic, body)) in COMMON_FIXTURES.iter().enumerate() {
            let mut symbols = PdbSymbols::default();
            let rva = 0x1000 + index;
            symbols.add_function_at_rva(rva, b"real".as_slice().into(), body, true);

            let names = &symbols.functions[&rva];
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].as_bytes(), *synthetic);
        }
    }
}
