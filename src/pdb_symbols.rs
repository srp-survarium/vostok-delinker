use pdb2::{FallibleIterator, RawString, TypeData, TypeIndex};

use std::collections::{BTreeMap, HashMap, btree_map};

use crate::Env;
use crate::utils::{ToUsize, leak};

#[derive(Default)]
pub struct PdbSymbols {
    pub functions: BTreeMap<usize, Vec<RawString<'static>>>,
    function_extents: BTreeMap<usize, usize>,
    incremental_trampolines: BTreeMap<usize, PdbIncrementalTrampoline>,
    text_data: HashMap<PdbModuleIndex, BTreeMap<usize, PdbTextData>>,
    text_symbols: HashMap<PdbModuleIndex, BTreeMap<usize, Vec<PdbTextSymbol>>>,
    pub imports: BTreeMap<usize, RawString<'static>>,
    pub strings: BTreeMap<usize, (RawString<'static>, Vec<u8>)>,

    pub constants: BTreeMap<usize, PdbDataSymbol>,
    pub statics: BTreeMap<usize, PdbDataSymbol>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PdbIncrementalTrampoline {
    target_rva: usize,
    size: usize,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PdbModuleIndex(usize);

impl PdbModuleIndex {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PdbTextSymbolScope {
    Local,
    Global,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PdbTextSymbolKind {
    Data,
    Label,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PdbTextSymbol {
    pub name: RawString<'static>,
    pub scope: PdbTextSymbolScope,
    pub kind: PdbTextSymbolKind,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PdbTextData {
    size: Option<usize>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FunctionRelocationField {
    Within { function_rva: usize },
    MissingFunction,
    UnknownExtent,
    OutsideExtent,
    FieldOverflow,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PdbDataSymbol {
    pub name: RawString<'static>,
    size: Option<usize>,
}

impl PdbDataSymbol {
    pub fn new(name: RawString<'static>, size: Option<usize>) -> Self {
        Self { name, size }
    }

    pub fn contains(self, symbol_rva: usize, target_rva: usize) -> bool {
        target_rva >= symbol_rva && self.size.is_none_or(|size| target_rva - symbol_rva < size)
    }

    fn fill_size_from(&mut self, other: Self) {
        if self.size.is_none() {
            self.size = other.size;
        }
    }
}

impl PdbSymbols {
    pub fn parse<S>(env: &Env, pdb: &mut pdb2::PDB<'static, S>) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self::default();
        let mut type_sizes = TypeSizeResolver::parse(pdb);

        this.iterate_symbol_table(env, &mut type_sizes)?;
        this.iterate_modules(env, pdb, &mut type_sizes)?;
        this.validate_incremental_trampolines(env)?;

        Ok(this)
    }

    fn iterate_symbol_table(
        &mut self,
        env: &Env,
        type_sizes: &mut TypeSizeResolver,
    ) -> anyhow::Result<()> {
        // Data symbols partially repeat Public symbols, but they also have unique symbols.
        //
        // Whenever available we would prefer Public symbols, since those are mangled and contain
        // type information.
        //
        // But we also want unique symbols.
        let mut static_data_symbols = vec![];
        let mut constant_data_symbols = vec![];
        let mut import_data_symbols = vec![];

        let mut symbols = env.symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            let symbol = symbol.parse()?;

            let (name, offset) = match &symbol {
                pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }) => (name, offset),
                pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. }) => (name, offset),
                _ => continue,
            };
            let name = *name;

            let symbol_rva = match env.iat_rva(*offset) {
                Some(rva) => rva,
                None => match () {
                    () if offset.section == env.text.id => env.text.rva + offset.offset.to_usize(),
                    () if offset.section == env.rdata.id => {
                        env.rdata.rva + offset.offset.to_usize()
                    }
                    () if offset.section == env.data.id => env.data.rva + offset.offset.to_usize(),
                    _ => continue,
                },
            };

            match symbol {
                pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })
                    if env.iat.is_some_and(|iat| iat.contains_rva(symbol_rva)) =>
                {
                    self.imports.entry(symbol_rva).or_insert(name);
                }

                pdb2::SymbolData::Data(pdb2::DataSymbol { .. })
                    if env.iat.is_some_and(|iat| iat.contains_rva(symbol_rva)) =>
                {
                    import_data_symbols.push((symbol_rva, name));
                }

                // @NOTE: There are more symbols in `.text`, which are not functions.
                // Seem to be useless though:
                // 0x1cba96: __imp_load__CoInitialize@4
                // 0x19963d: __nosnan2
                pdb2::SymbolData::Public(pdb2::PublicSymbol { function, .. }) if function => {
                    assert_eq!(offset.section, env.text.id);

                    self.add_function_at_rva(symbol_rva, name, None)?;
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
                    let _old_symbol = self
                        .constants
                        .insert(symbol_rva, PdbDataSymbol::new(name, None));
                }

                pdb2::SymbolData::Public(pdb2::PublicSymbol { .. })
                    if offset.section == env.data.id =>
                {
                    let old_symbol = self
                        .statics
                        .insert(symbol_rva, PdbDataSymbol::new(name, None));
                    assert_eq!(old_symbol, None, "Static symbols cannot repeat");
                }

                // Unmangled data symbols to cover missing spots.
                pdb2::SymbolData::Data(pdb2::DataSymbol { type_index, .. })
                    if offset.section == env.rdata.id =>
                {
                    constant_data_symbols.push((
                        symbol_rva,
                        PdbDataSymbol::new(name, type_sizes.size_of(type_index)),
                    ));
                }
                pdb2::SymbolData::Data(pdb2::DataSymbol { type_index, .. })
                    if offset.section == env.data.id =>
                {
                    static_data_symbols.push((
                        symbol_rva,
                        PdbDataSymbol::new(name, type_sizes.size_of(type_index)),
                    ));
                }
                _ => {}
            }
        }
        for (symbol_rva, name) in import_data_symbols {
            self.imports.entry(symbol_rva).or_insert(name);
        }
        for (symbol_rva, symbol) in static_data_symbols {
            match self.statics.entry(symbol_rva) {
                btree_map::Entry::Vacant(entry) => _ = entry.insert(symbol),
                btree_map::Entry::Occupied(mut entry) => entry.get_mut().fill_size_from(symbol),
            }
        }

        for (symbol_rva, symbol) in constant_data_symbols {
            match self.constants.entry(symbol_rva) {
                btree_map::Entry::Vacant(entry) => _ = entry.insert(symbol),
                btree_map::Entry::Occupied(mut entry) => entry.get_mut().fill_size_from(symbol),
            }
        }

        Ok(())
    }

    fn iterate_modules<S>(
        &mut self,

        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,
        type_sizes: &mut TypeSizeResolver,
    ) -> anyhow::Result<()>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut modules = env.dbi.modules()?;
        let mut module_ordinal = 0;

        while let Some(module) = modules.next()? {
            let module_index = PdbModuleIndex::new(module_ordinal);
            module_ordinal += 1;
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
                    })) => self.add_function_symbol(env, name, offset, len.to_usize())?,
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        name, offset, len, ..
                    })) => self.add_function_symbol(env, name, offset, len.to_usize())?,

                    Ok(pdb2::SymbolData::Trampoline(pdb2::TrampolineSymbol {
                        tramp_type: pdb2::TrampolineType::Incremental,
                        size,
                        thunk,
                        target,
                    })) => self.add_incremental_trampoline(env, thunk, target, size.into())?,

                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol {
                        global,
                        offset,
                        name,
                        type_index,
                        ..
                    })) => {
                        if let Some(symbol_rva) = env.iat_rva(offset) {
                            self.imports.entry(symbol_rva).or_insert(name);
                            continue;
                        }
                        let symbol_rva = match () {
                            () if offset.section == env.text.id => {
                                env.text.rva + offset.offset.to_usize()
                            }
                            () if offset.section == env.rdata.id => {
                                env.rdata.rva + offset.offset.to_usize()
                            }
                            () if offset.section == env.data.id => {
                                env.data.rva + offset.offset.to_usize()
                            }
                            _ => continue,
                        };

                        match () {
                            () if offset.section == env.text.id => {
                                self.add_text_data_at_rva(
                                    module_index,
                                    symbol_rva,
                                    name,
                                    type_sizes.size_of(type_index),
                                    if global {
                                        PdbTextSymbolScope::Global
                                    } else {
                                        PdbTextSymbolScope::Local
                                    },
                                )?;
                            }
                            () if offset.section == env.rdata.id => {
                                let _old_symbol = self.constants.insert(
                                    symbol_rva,
                                    PdbDataSymbol::new(name, type_sizes.size_of(type_index)),
                                );
                            }
                            () if offset.section == env.data.id => {
                                // Prefer symbol names from modules.
                                // As those are closer to the original symbols.
                                // For comparison see: `survarium::damage_zone_cook::damage_zone_cook`.
                                let _old_symbol = self.statics.insert(
                                    symbol_rva,
                                    PdbDataSymbol::new(name, type_sizes.size_of(type_index)),
                                );
                            }
                            _ => continue,
                        };
                    }

                    Ok(pdb2::SymbolData::Label(pdb2::LabelSymbol { offset, name, .. }))
                        if offset.section == env.text.id =>
                    {
                        let symbol_rva = env.text.rva + offset.offset.to_usize();
                        self.add_text_symbol_at_rva(
                            module_index,
                            symbol_rva,
                            name,
                            PdbTextSymbolScope::Local,
                            PdbTextSymbolKind::Label,
                        );
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
        size: usize,
    ) -> anyhow::Result<()> {
        let symbol_rva = env.text.rva + offset.offset.to_usize();
        self.add_function_at_rva(symbol_rva, name, Some(size))
    }

    pub(crate) fn add_function_at_rva(
        &mut self,
        symbol_rva: usize,
        name: RawString<'static>,
        size: Option<usize>,
    ) -> anyhow::Result<()> {
        if let Some(size) = size {
            symbol_rva
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("PDB function extent overflows RVA"))?;
            match self.function_extents.entry(symbol_rva) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(size);
                }
                btree_map::Entry::Occupied(entry) if *entry.get() == size => {}
                btree_map::Entry::Occupied(entry) => anyhow::bail!(
                    "PDB function records at RVA {symbol_rva:#x} disagree on size: {} and {size}",
                    entry.get()
                ),
            }
        }
        Self::push_function_name(self.functions.entry(symbol_rva).or_default(), name);
        Ok(())
    }

    fn add_incremental_trampoline(
        &mut self,
        env: &Env,
        thunk: pdb2::PdbInternalSectionOffset,
        target: pdb2::PdbInternalSectionOffset,
        size: usize,
    ) -> anyhow::Result<()> {
        if thunk.section != env.text.id || target.section != env.text.id {
            anyhow::bail!("PDB incremental trampoline is not contained in .text");
        }
        let thunk_rva = env
            .text
            .rva
            .checked_add(thunk.offset.to_usize())
            .ok_or_else(|| anyhow::anyhow!("PDB incremental trampoline RVA overflows"))?;
        let target_rva = env
            .text
            .rva
            .checked_add(target.offset.to_usize())
            .ok_or_else(|| anyhow::anyhow!("PDB incremental trampoline target RVA overflows"))?;
        self.add_incremental_trampoline_at_rva(thunk_rva, target_rva, size)
    }

    pub(crate) fn add_incremental_trampoline_at_rva(
        &mut self,
        thunk_rva: usize,
        target_rva: usize,
        size: usize,
    ) -> anyhow::Result<()> {
        let trampoline = PdbIncrementalTrampoline { target_rva, size };
        match self.incremental_trampolines.entry(thunk_rva) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(trampoline);
            }
            btree_map::Entry::Occupied(entry) if *entry.get() == trampoline => {}
            btree_map::Entry::Occupied(_) => {
                anyhow::bail!("PDB incremental trampoline records at RVA {thunk_rva:#x} disagree")
            }
        }
        Ok(())
    }

    fn validate_incremental_trampolines(&mut self, env: &Env) -> anyhow::Result<()> {
        self.validate_incremental_trampolines_in_text(env.text.rva, env.text.data)
    }

    pub(crate) fn validate_incremental_trampolines_in_text(
        &mut self,
        text_rva: usize,
        text_data: &[u8],
    ) -> anyhow::Result<()> {
        const JMP_REL32: u8 = 0xe9;
        const JMP_REL32_SIZE: usize = 5;

        for (&thunk_rva, trampoline) in &self.incremental_trampolines {
            if trampoline.size != JMP_REL32_SIZE {
                anyhow::bail!(
                    "PDB incremental trampoline at RVA {thunk_rva:#x} has unsupported size {}",
                    trampoline.size
                );
            }
            if self
                .incremental_trampolines
                .contains_key(&trampoline.target_rva)
            {
                anyhow::bail!(
                    "PDB incremental trampoline at RVA {thunk_rva:#x} targets another trampoline"
                );
            }
            if !self.function_extents.contains_key(&trampoline.target_rva) {
                anyhow::bail!(
                    "PDB incremental trampoline at RVA {thunk_rva:#x} has no exact target procedure"
                );
            }
            let offset = thunk_rva
                .checked_sub(text_rva)
                .ok_or_else(|| anyhow::anyhow!("PDB incremental trampoline precedes .text"))?;
            let bytes = text_data
                .get(offset..offset + JMP_REL32_SIZE)
                .ok_or_else(|| anyhow::anyhow!("PDB incremental trampoline exceeds .text"))?;
            if bytes[0] != JMP_REL32 {
                anyhow::bail!("PDB incremental trampoline at RVA {thunk_rva:#x} is not JMP rel32");
            }
            let displacement = i32::from_le_bytes(bytes[1..].try_into()?);
            let decoded_target = i64::try_from(thunk_rva)?
                .checked_add(i64::try_from(JMP_REL32_SIZE)?)
                .and_then(|next| next.checked_add(i64::from(displacement)))
                .and_then(|target| usize::try_from(target).ok())
                .ok_or_else(|| anyhow::anyhow!("incremental trampoline target overflows RVA"))?;
            if decoded_target != trampoline.target_rva {
                anyhow::bail!(
                    "PDB incremental trampoline at RVA {thunk_rva:#x} disagrees with PE target"
                );
            }
        }

        for thunk_rva in self.incremental_trampolines.keys() {
            self.functions.remove(thunk_rva);
            self.function_extents.remove(thunk_rva);
        }
        Ok(())
    }

    pub fn resolve_incremental_trampoline(&self, target_rva: usize) -> usize {
        self.incremental_trampolines
            .get(&target_rva)
            .map_or(target_rva, |trampoline| trampoline.target_rva)
    }

    pub fn is_incremental_trampoline(&self, rva: usize) -> bool {
        self.incremental_trampolines.contains_key(&rva)
    }

    pub(crate) fn add_text_data_at_rva(
        &mut self,
        module: PdbModuleIndex,
        symbol_rva: usize,
        name: RawString<'static>,
        size: Option<usize>,
        scope: PdbTextSymbolScope,
    ) -> anyhow::Result<()> {
        if let Some(size) = size {
            symbol_rva
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("PDB text data extent overflows RVA"))?;
        }
        let text_data = self.text_data.entry(module).or_default();
        match text_data.entry(symbol_rva) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(PdbTextData { size });
            }
            btree_map::Entry::Occupied(mut entry) => match (entry.get().size, size) {
                (Some(left), Some(right)) if left != right => anyhow::bail!(
                    "PDB text data records at RVA {symbol_rva:#x} disagree on size: {left} and {right}"
                ),
                (None, Some(_)) => entry.get_mut().size = size,
                _ => {}
            },
        }
        let kind = if name.as_bytes().starts_with(b"$L") {
            PdbTextSymbolKind::Label
        } else {
            PdbTextSymbolKind::Data
        };
        self.add_text_symbol_at_rva(module, symbol_rva, name, scope, kind);
        Ok(())
    }

    pub(crate) fn add_text_symbol_at_rva(
        &mut self,
        module: PdbModuleIndex,
        symbol_rva: usize,
        name: RawString<'static>,
        scope: PdbTextSymbolScope,
        kind: PdbTextSymbolKind,
    ) {
        let symbols = self
            .text_symbols
            .entry(module)
            .or_default()
            .entry(symbol_rva)
            .or_default();
        if !symbols.iter().any(|symbol| {
            symbol.name.as_bytes() == name.as_bytes()
                && symbol.scope == scope
                && symbol.kind == kind
        }) {
            symbols.push(PdbTextSymbol { name, scope, kind });
        }
    }

    pub(crate) fn function_extent(&self, function_rva: usize) -> Option<std::ops::Range<usize>> {
        let size = self.function_extents.get(&function_rva).copied()?;
        Some(function_rva..function_rva.checked_add(size)?)
    }

    fn text_data_extent(
        &self,
        module: PdbModuleIndex,
        function_rva: usize,
        data_rva: usize,
    ) -> anyhow::Result<Option<std::ops::Range<usize>>> {
        let Some(function_extent) = self.function_extent(function_rva) else {
            return Ok(None);
        };
        if !function_extent.contains(&data_rva) {
            return Ok(None);
        }
        let Some(text_data) = self.text_data.get(&module) else {
            return Ok(None);
        };
        let Some(data) = text_data.get(&data_rva) else {
            return Ok(None);
        };
        let next_start = text_data
            .range(data_rva.saturating_add(1)..function_extent.end)
            .next()
            .map(|(rva, _)| *rva)
            .unwrap_or(function_extent.end);
        let end = match data.size {
            Some(size) => data_rva
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("PDB text data extent overflows RVA"))?,
            None => next_start,
        };
        anyhow::ensure!(
            end <= next_start,
            "PDB text data extent overlaps another text data record"
        );
        Ok(Some(data_rva..end))
    }

    pub(crate) fn text_data_extents(
        &self,
        module: PdbModuleIndex,
        function_rva: usize,
    ) -> anyhow::Result<Vec<std::ops::Range<usize>>> {
        let Some(function_extent) = self.function_extent(function_rva) else {
            return Ok(Vec::new());
        };
        let Some(text_data) = self.text_data.get(&module) else {
            return Ok(Vec::new());
        };
        text_data
            .range(function_extent)
            .map(|(data_rva, _)| {
                self.text_data_extent(module, function_rva, *data_rva)?
                    .ok_or_else(|| anyhow::anyhow!("PDB text data has no containing procedure"))
            })
            .collect()
    }

    pub(crate) fn text_symbols(
        &self,
        module: PdbModuleIndex,
    ) -> Option<&BTreeMap<usize, Vec<PdbTextSymbol>>> {
        self.text_symbols.get(&module)
    }

    pub(crate) fn text_symbols_at_rva(
        &self,
        module: PdbModuleIndex,
        rva: usize,
    ) -> &[PdbTextSymbol] {
        self.text_symbols(module)
            .and_then(|symbols| symbols.get(&rva))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn relocation_field_in_function(
        &self,
        function_rva: usize,
        site_rva: usize,
    ) -> FunctionRelocationField {
        if !self.functions.contains_key(&function_rva) {
            return FunctionRelocationField::MissingFunction;
        }
        let Some(size) = self.function_extents.get(&function_rva).copied() else {
            return FunctionRelocationField::UnknownExtent;
        };
        let Some(site_end) = site_rva.checked_add(std::mem::size_of::<u32>()) else {
            return FunctionRelocationField::FieldOverflow;
        };
        let Some(function_end) = function_rva.checked_add(size) else {
            return FunctionRelocationField::FieldOverflow;
        };
        if function_rva <= site_rva && site_end <= function_end {
            FunctionRelocationField::Within { function_rva }
        } else {
            FunctionRelocationField::OutsideExtent
        }
    }

    pub fn relocation_field_owner(&self, site_rva: usize) -> FunctionRelocationField {
        let Some((function_rva, _)) = self.functions.range(..=site_rva).next_back() else {
            return FunctionRelocationField::MissingFunction;
        };
        self.relocation_field_in_function(*function_rva, site_rva)
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

struct TypeSizeResolver {
    finder: Option<pdb2::TypeFinder<'static>>,
    cache: HashMap<TypeIndex, Option<usize>>,
}

impl TypeSizeResolver {
    fn parse<S>(pdb: &mut pdb2::PDB<'static, S>) -> Self
    where
        S: pdb2::Source<'static> + 'static,
    {
        let Ok(type_information) = pdb.type_information() else {
            return Self {
                finder: None,
                cache: HashMap::new(),
            };
        };
        let type_information = leak(type_information);
        let mut finder = type_information.finder();
        let mut iter = type_information.iter();
        loop {
            match iter.next() {
                Ok(Some(_)) => finder.update(&iter),
                Ok(None) => break,
                Err(_) => {
                    return Self {
                        finder: None,
                        cache: HashMap::new(),
                    };
                }
            }
        }

        Self {
            finder: Some(finder),
            cache: HashMap::new(),
        }
    }

    fn size_of(&mut self, index: TypeIndex) -> Option<usize> {
        if let Some(size) = self.cache.get(&index) {
            return *size;
        }

        let Some(finder) = &self.finder else {
            return None;
        };

        self.cache.insert(index, None);
        let size = match finder.find(index).and_then(|typ| typ.parse()) {
            Ok(TypeData::Primitive(typ)) => primitive_size(typ.kind, typ.indirection),
            Ok(TypeData::Pointer(typ)) => {
                let size = typ.attributes.size();
                (size != 0).then_some(usize::from(size))
            }
            Ok(TypeData::Modifier(typ)) => self.size_of(typ.underlying_type),
            Ok(TypeData::Array(typ)) => typ
                .dimensions
                .last()
                .copied()
                .map(|size| size.to_usize())
                .filter(|&size| size != 0),
            Ok(TypeData::Class(typ)) => usize::try_from(typ.size).ok().filter(|&size| size != 0),
            Ok(TypeData::Union(typ)) => usize::try_from(typ.size).ok().filter(|&size| size != 0),
            Ok(TypeData::Enumeration(typ)) => self.size_of(typ.underlying_type),
            _ => None,
        };
        self.cache.insert(index, size);
        size
    }
}

fn primitive_size(
    kind: pdb2::PrimitiveKind,
    indirection: Option<pdb2::Indirection>,
) -> Option<usize> {
    if let Some(indirection) = indirection {
        return match indirection {
            pdb2::Indirection::Near16 => Some(2),
            pdb2::Indirection::Far16 | pdb2::Indirection::Huge16 => Some(4),
            pdb2::Indirection::Near32 => Some(4),
            pdb2::Indirection::Far32 => Some(6),
            pdb2::Indirection::Near64 => Some(8),
            pdb2::Indirection::Near128 => Some(16),
        };
    }

    match kind {
        pdb2::PrimitiveKind::NoType | pdb2::PrimitiveKind::Void => None,
        pdb2::PrimitiveKind::Char
        | pdb2::PrimitiveKind::UChar
        | pdb2::PrimitiveKind::RChar
        | pdb2::PrimitiveKind::Char8
        | pdb2::PrimitiveKind::I8
        | pdb2::PrimitiveKind::U8
        | pdb2::PrimitiveKind::Bool8 => Some(1),
        pdb2::PrimitiveKind::WChar
        | pdb2::PrimitiveKind::RChar16
        | pdb2::PrimitiveKind::Short
        | pdb2::PrimitiveKind::UShort
        | pdb2::PrimitiveKind::I16
        | pdb2::PrimitiveKind::U16
        | pdb2::PrimitiveKind::F16
        | pdb2::PrimitiveKind::Bool16 => Some(2),
        pdb2::PrimitiveKind::RChar32
        | pdb2::PrimitiveKind::Long
        | pdb2::PrimitiveKind::ULong
        | pdb2::PrimitiveKind::I32
        | pdb2::PrimitiveKind::U32
        | pdb2::PrimitiveKind::F32
        | pdb2::PrimitiveKind::F32PP
        | pdb2::PrimitiveKind::Bool32
        | pdb2::PrimitiveKind::HRESULT => Some(4),
        pdb2::PrimitiveKind::Quad
        | pdb2::PrimitiveKind::UQuad
        | pdb2::PrimitiveKind::I64
        | pdb2::PrimitiveKind::U64
        | pdb2::PrimitiveKind::F64
        | pdb2::PrimitiveKind::Complex32
        | pdb2::PrimitiveKind::Bool64 => Some(8),
        pdb2::PrimitiveKind::F48 => Some(6),
        pdb2::PrimitiveKind::F80 => Some(10),
        pdb2::PrimitiveKind::Octa
        | pdb2::PrimitiveKind::UOcta
        | pdb2::PrimitiveKind::I128
        | pdb2::PrimitiveKind::U128
        | pdb2::PrimitiveKind::F128
        | pdb2::PrimitiveKind::Complex64 => Some(16),
        pdb2::PrimitiveKind::Complex80 => Some(20),
        pdb2::PrimitiveKind::Complex128 => Some(32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_incremental_trampoline_bytes_and_removes_linker_function() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1005, RawString::from(&b"linker-thunk"[..]), Some(5))
            .unwrap();
        symbols
            .add_function_at_rva(0x1100, RawString::from(&b"body"[..]), Some(1))
            .unwrap();
        symbols
            .add_incremental_trampoline_at_rva(0x1005, 0x1100, 5)
            .unwrap();

        let mut text = vec![0; 0x101];
        text[5..10].copy_from_slice(&[0xe9, 0xf6, 0x00, 0x00, 0x00]);
        symbols
            .validate_incremental_trampolines_in_text(0x1000, &text)
            .unwrap();

        assert_eq!(symbols.resolve_incremental_trampoline(0x1005), 0x1100);
        assert_eq!(symbols.resolve_incremental_trampoline(0x1006), 0x1006);
        assert!(!symbols.functions.contains_key(&0x1005));
        assert!(!symbols.function_extents.contains_key(&0x1005));
        assert!(symbols.functions.contains_key(&0x1100));
    }

    #[test]
    fn rejects_incremental_trampoline_metadata_that_disagrees_with_the_image() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1100, RawString::from(&b"body"[..]), Some(1))
            .unwrap();
        symbols
            .add_incremental_trampoline_at_rva(0x1005, 0x1100, 5)
            .unwrap();
        let text = vec![0; 0x101];
        assert!(
            symbols
                .validate_incremental_trampolines_in_text(0x1000, &text)
                .unwrap_err()
                .to_string()
                .contains("is not JMP rel32")
        );
    }

    #[test]
    fn rejects_incremental_trampoline_to_public_symbol_without_procedure() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1100, RawString::from(&b"public-only"[..]), None)
            .unwrap();
        symbols
            .add_incremental_trampoline_at_rva(0x1005, 0x1100, 5)
            .unwrap();
        let mut text = vec![0; 0x101];
        text[5..10].copy_from_slice(&[0xe9, 0xf6, 0x00, 0x00, 0x00]);

        let error = symbols
            .validate_incremental_trampolines_in_text(0x1000, &text)
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no exact target procedure"));
    }

    #[test]
    fn rejects_conflicting_incremental_trampoline_records() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_incremental_trampoline_at_rva(0x1005, 0x1100, 5)
            .unwrap();
        let error = symbols
            .add_incremental_trampoline_at_rva(0x1005, 0x1200, 5)
            .unwrap_err()
            .to_string();
        assert!(error.contains("records at RVA 0x1005 disagree"));
    }

    #[test]
    fn retains_distinct_pdb_names_at_one_function_rva() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"real_a"[..]), Some(0x20))
            .unwrap();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"real_b"[..]), Some(0x20))
            .unwrap();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"real_a"[..]), Some(0x20))
            .unwrap();

        let names = &symbols.functions[&0x1000];
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].as_bytes(), b"real_a");
        assert_eq!(names[1].as_bytes(), b"real_b");
    }

    #[test]
    fn duplicate_function_records_must_agree_on_extent() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"real_a"[..]), Some(0x20))
            .unwrap();
        let error = symbols
            .add_function_at_rva(0x1000, RawString::from(&b"real_b"[..]), Some(0x24))
            .unwrap_err()
            .to_string();
        assert!(error.contains("RVA 0x1000 disagree on size: 32 and 36"));
        assert_eq!(symbols.functions[&0x1000].len(), 1);
    }

    #[test]
    fn text_data_extent_uses_type_size_or_next_pdb_boundary() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"owner"[..]), Some(0x30))
            .unwrap();
        symbols
            .add_text_data_at_rva(
                PdbModuleIndex::new(0),
                0x1010,
                RawString::from(&b"typed"[..]),
                Some(8),
                PdbTextSymbolScope::Local,
            )
            .unwrap();
        symbols
            .add_text_data_at_rva(
                PdbModuleIndex::new(0),
                0x1020,
                RawString::from(&b"untyped"[..]),
                None,
                PdbTextSymbolScope::Local,
            )
            .unwrap();

        assert_eq!(
            symbols
                .text_data_extent(PdbModuleIndex::new(0), 0x1000, 0x1010)
                .unwrap(),
            Some(0x1010..0x1018)
        );
        assert_eq!(
            symbols
                .text_data_extent(PdbModuleIndex::new(0), 0x1000, 0x1020)
                .unwrap(),
            Some(0x1020..0x1030)
        );
    }

    #[test]
    fn text_data_extent_rejects_overlap_with_next_record() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"owner"[..]), Some(0x30))
            .unwrap();
        symbols
            .add_text_data_at_rva(
                PdbModuleIndex::new(0),
                0x1010,
                RawString::from(&b"left"[..]),
                Some(0x18),
                PdbTextSymbolScope::Local,
            )
            .unwrap();
        symbols
            .add_text_data_at_rva(
                PdbModuleIndex::new(0),
                0x1020,
                RawString::from(&b"right"[..]),
                None,
                PdbTextSymbolScope::Local,
            )
            .unwrap();

        let error = symbols
            .text_data_extent(PdbModuleIndex::new(0), 0x1000, 0x1010)
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlaps another text data record"));
    }

    #[test]
    fn msvc_compiler_text_data_name_keeps_coff_label_kind() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_text_data_at_rva(
                PdbModuleIndex::new(0),
                0x1010,
                RawString::from(&b"$L1193"[..]),
                None,
                PdbTextSymbolScope::Local,
            )
            .unwrap();

        assert_eq!(
            symbols.text_symbols[&PdbModuleIndex::new(0)][&0x1010][0].kind,
            PdbTextSymbolKind::Label
        );
    }

    #[test]
    fn text_data_and_labels_remain_module_scoped_at_folded_rva() {
        let left = PdbModuleIndex::new(0);
        let right = PdbModuleIndex::new(1);
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"folded"[..]), Some(0x20))
            .unwrap();
        symbols
            .add_text_data_at_rva(
                left,
                0x1010,
                RawString::from(&b"$L_left"[..]),
                Some(4),
                PdbTextSymbolScope::Local,
            )
            .unwrap();
        symbols
            .add_text_data_at_rva(
                right,
                0x1010,
                RawString::from(&b"$L_right"[..]),
                Some(8),
                PdbTextSymbolScope::Local,
            )
            .unwrap();

        let left_extents = symbols.text_data_extents(left, 0x1000).unwrap();
        let right_extents = symbols.text_data_extents(right, 0x1000).unwrap();
        assert_eq!(left_extents.len(), 1);
        assert_eq!(right_extents.len(), 1);
        assert_eq!(left_extents[0], 0x1010..0x1014);
        assert_eq!(right_extents[0], 0x1010..0x1018);
        assert_eq!(
            symbols.text_symbols_at_rva(left, 0x1010)[0].name.as_bytes(),
            b"$L_left"
        );
        assert_eq!(
            symbols.text_symbols_at_rva(right, 0x1010)[0]
                .name
                .as_bytes(),
            b"$L_right"
        );
    }

    #[test]
    fn relocation_field_requires_a_known_complete_function_extent() {
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"known"[..]), Some(0x10))
            .unwrap();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"public_only"[..]), None)
            .unwrap();

        assert_eq!(
            symbols.relocation_field_owner(0x100c),
            FunctionRelocationField::Within {
                function_rva: 0x1000
            }
        );
        assert_eq!(
            symbols.relocation_field_owner(0x100d),
            FunctionRelocationField::OutsideExtent
        );
        assert_eq!(
            symbols.relocation_field_owner(0x1010),
            FunctionRelocationField::OutsideExtent
        );
        assert_eq!(
            symbols.relocation_field_owner(0x2000),
            FunctionRelocationField::UnknownExtent
        );
        assert_eq!(
            symbols.relocation_field_in_function(0x3000, 0x3000),
            FunctionRelocationField::MissingFunction
        );
        assert_eq!(
            symbols.relocation_field_in_function(0x1000, usize::MAX - 2),
            FunctionRelocationField::FieldOverflow
        );
    }

    #[test]
    fn known_data_size_rejects_the_end_boundary() {
        let symbol = PdbDataSymbol::new(RawString::from(&b"table"[..]), Some(8));
        assert!(symbol.contains(0x1000, 0x1000));
        assert!(symbol.contains(0x1000, 0x1007));
        assert!(!symbol.contains(0x1000, 0x0fff));
        assert!(!symbol.contains(0x1000, 0x1008));
    }

    #[test]
    fn unknown_data_size_does_not_restrict_the_fallback() {
        let symbol = PdbDataSymbol::new(RawString::from(&b"table"[..]), None);
        assert!(symbol.contains(0x1000, 0x1000));
        assert!(symbol.contains(0x1000, 0x2000));
    }

    #[test]
    fn data_record_adds_size_without_replacing_public_name() {
        let mut public = PdbDataSymbol::new(RawString::from(&b"?table@@3PAHA"[..]), None);
        let data = PdbDataSymbol::new(RawString::from(&b"table"[..]), Some(16));
        public.fill_size_from(data);
        assert_eq!(public.name.as_bytes(), b"?table@@3PAHA");
        assert!(public.contains(0x1000, 0x100f));
        assert!(!public.contains(0x1000, 0x1010));
    }

    #[test]
    fn codeview_complex_sizes_cover_both_components() {
        assert_eq!(
            primitive_size(pdb2::PrimitiveKind::Complex32, None),
            Some(8)
        );
        assert_eq!(
            primitive_size(pdb2::PrimitiveKind::Complex64, None),
            Some(16)
        );
        assert_eq!(
            primitive_size(pdb2::PrimitiveKind::Complex80, None),
            Some(20)
        );
        assert_eq!(
            primitive_size(pdb2::PrimitiveKind::Complex128, None),
            Some(32)
        );
    }
}
