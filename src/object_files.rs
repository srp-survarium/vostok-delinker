use crate::Env;
use crate::data_manifest::{DataDefinition, DataManifest, DataScope, DataStorage};
use crate::pdb_symbols::PdbSymbols;
use crate::relocs::{RelocKind, RelocationEncoding};
use crate::symbol_matcher::{SymbolMatcher, canonical_name};
use crate::utils::{ToU64, ToUsize, contains, leak};

use std::collections::{BTreeMap, HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use pdb2::{FallibleIterator, RawString};

use object::SectionKind;

pub struct ObjectFiles<'a> {
    pub objects: HashMap<&'a [u8], ObjectFile>,
}

pub struct ObjectFile {
    pub object: object::write::Object<'static>,
    pub data_section_id: object::write::SectionId,
    pub rdata_section_id: object::write::SectionId,
    pub bss_section_id: Option<object::write::SectionId>,
    pub text_section_id: object::write::SectionId,
}

#[derive(Copy, Clone)]
pub struct ObjectOffset {
    offset: u64,
    section_id: object::write::SectionId,
}

#[derive(Copy, Clone)]
pub enum ObjectLocation {
    Offset(ObjectOffset),
    Extern,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum TargetMaterialization {
    Materialize,
    ReferenceOnly,
}

#[derive(Copy, Clone)]
enum SymbolReuse {
    AlwaysCreate,
    ReuseIfDefined,
}

impl ObjectFiles<'_> {
    pub fn parse<'s, S>(
        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,

        symbols: &'s PdbSymbols,
        coff_data: &[u8],
        mut relocs_rva: BTreeMap<usize, RelocKind<'s>>,

        engine_path: &[u8],
        pad_empty_rdata: bool,
        matcher: &SymbolMatcher,
        data_manifest: &DataManifest,
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self {
            objects: HashMap::new(),
        };

        let definitions = data_manifest.definitions_in_emission_order();

        for definition in &definitions {
            let definition_end = definition.rva.checked_add(definition.size).unwrap();
            let section = match definition.storage {
                DataStorage::Rdata => env.rdata,
                DataStorage::Data | DataStorage::Bss => env.data,
            };
            if definition.rva < section.rva || definition_end > section.rva + section.size {
                anyhow::bail!("data manifest storage does not match the PE section");
            }
            let object_file = this
                .objects
                .entry(definition.object)
                .or_insert_with(|| ObjectFile::empty(pad_empty_rdata));
            object_file.add_data_definition(*definition, coff_data)?;
        }
        for definition in &definitions {
            this.objects
                .get_mut(definition.object)
                .unwrap()
                .add_data_relocations(
                    *definition,
                    matcher,
                    coff_data,
                    &relocs_rva,
                    data_manifest,
                )?;
        }

        let mut modules = env.dbi.modules()?;
        while let Some(module) = modules.next()? {
            let Some(module_info) = pdb.module_info(&module)? else {
                continue;
            };
            let module_info = leak(module_info);

            let program = module_info.line_program()?;
            let mut iter = module_info.symbols()?;

            while let Some(symbol) = iter.next()? {
                let (fun_name, fun_offset, fun_size) = match symbol.parse() {
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => (name, offset, len.to_usize()),
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        name, offset, len, ..
                    })) => (name, offset, len.to_usize()),
                    _ => continue,
                };

                let Some(filename) = get_function_location(
                    &program,
                    env.string_table,
                    fun_name,
                    fun_offset,
                    engine_path,
                )?
                else {
                    continue;
                };

                let fun_rva = env.text.rva + fun_offset.offset.to_usize();
                let fun_bytes = resolve_relative_relocations(
                    env,
                    fun_rva,
                    fun_size,
                    symbols,
                    coff_data,
                    &mut relocs_rva,
                )?;

                let object_file = this
                    .objects
                    .entry(filename)
                    .or_insert_with(|| ObjectFile::empty(pad_empty_rdata));

                let fun_name = match symbols.functions.get(&fun_rva) {
                    Some(overloads) => matcher.pick(overloads, canonical_name(overloads)),
                    _ => fun_name,
                };

                let fun_offset_in_coff_text = object_file.add_function(fun_name, &fun_bytes);

                for (reloc_rva, reloc_kind) in relocs_rva.range(fun_rva..fun_rva + fun_size) {
                    let reloc_rva = *reloc_rva;
                    let reloc_kind = *reloc_kind;

                    let reloc_offset_in_fun = reloc_rva - fun_rva;
                    let reloc_offset_in_coff_text = fun_offset_in_coff_text + reloc_offset_in_fun;

                    // Fresh per top-level reloc (each pointer chain is independent).
                    let mut visited = HashSet::new();
                    object_file.add_relocation_at(
                        reloc_kind,
                        reloc_offset_in_coff_text,
                        matcher,
                        coff_data,
                        &relocs_rva,
                        &mut visited,
                        data_manifest,
                        TargetMaterialization::Materialize,
                    )?;
                }
            }
        }

        Ok(this)
    }

    pub fn write(self, base: &std::path::Path) -> anyhow::Result<()> {
        let base_len = base.as_os_str().as_encoded_bytes().len();
        let mut path = base.to_path_buf();

        for (prefix, object_file) in self.objects {
            path.as_mut_os_string().truncate(base_len);

            let prefix = prefix
                .iter()
                .map(|&c| match c {
                    b'\\' => '/',
                    _ => char::from(c),
                })
                .collect::<String>();
            path.as_mut_os_string().push("/");
            path.as_mut_os_string().push(&prefix);
            path.as_mut_os_string().push(".obj");

            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, object_file.object.write()?)?;
        }
        Ok(())
    }
}

impl ObjectFile {
    fn empty(pad_rdata: bool) -> Self {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Coff,
            object::Architecture::I386,
            object::Endianness::Little,
        );
        object.set_mangling(object::write::Mangling::None);

        let data_section_id = object.add_section(vec![], b".data".into(), SectionKind::Data);
        let rdata_section_id =
            object.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData);
        let text_section_id = object.add_section(vec![], b".text".into(), SectionKind::Text);

        // objdiff considers allocations to match if name is equal OR(!) offset
        // into reloc table is the same.
        //
        // This makes different relocations with different data and different names
        // to match, if they offsets match. These 4 bytes prevent that.
        if pad_rdata {
            object.append_section_data(rdata_section_id, &0_u32.to_le_bytes(), 4);
        }

        Self {
            object,
            data_section_id,
            rdata_section_id,
            bss_section_id: None,
            text_section_id,
        }
    }
}

/// Returns object file location for a given function.
//
// @NOTE: This function will leak memory in some cases.
// This simplifies string passing, and shouldn't matter for this script.
fn get_function_location(
    program: &pdb2::LineProgram<'static>,
    string_table: &'static pdb2::StringTable<'static>,

    fun_name: RawString<'static>,
    fun_offset: pdb2::PdbInternalSectionOffset,

    engine_path: &[u8],
) -> anyhow::Result<Option<&'static [u8]>> {
    let mut filename = None;

    let mut lines = program.lines_for_symbol(fun_offset);
    // Extracting only a single line should be enough to find a source file.
    if let Some(line_info) = lines.next()? {
        let file_info = program.get_file_info(line_info.file_index)?;
        filename = Some(string_table.get(file_info.name)?);
    }

    let location: &'static [u8] = match filename {
        Some(filename) => match filename.as_bytes().strip_prefix(engine_path) {
            Some(filename) => filename,
            None => return Ok(None),
        },
        None => match fun_name.as_bytes() {
            name if !contains(name, b"::") && !name.contains(&b' ') => b"_msvc_internal\\c_lang",
            name => {
                let name = name.strip_prefix(b"[thunk]:").unwrap_or(name);
                let name = name.strip_prefix(b"`").unwrap_or(name);

                let is_bullet = |name: &[u8]| {
                    name.starts_with(b"bt")
                        && name.len() > b"bt".len()
                        && name[b"bt".len()].is_ascii_uppercase()
                };

                match name {
                    name if is_bullet(name) => b"_msvc_internal\\bullet",
                    name => match name
                        .windows("::".len())
                        .position(|c| c == b"::" || c.starts_with(b"<"))
                    {
                        None => b"_msvc_internal\\cpp_lang",
                        Some(pos) => {
                            let mut path = b"_msvc_internal\\".to_vec();
                            path.extend_from_slice(&name[0..pos]);
                            path.leak()
                        }
                    },
                }
            }
        },
    };

    Ok(Some(location))
}

/// Resolve external relative jumps in the function as relocations.
///
/// And return the final resolved function assembly.
// @NOTE: There is no reason to grow `relocs_rva`, since these allocations
// are specific to the current function and don't need to be kept alive after
// the function is processed.
//
// At the same time `relocs_rva` sorts automatically!
fn resolve_relative_relocations<'s>(
    env: &Env,

    fun_rva: usize,
    fun_size: usize,

    symbols: &'s PdbSymbols,

    coff_data: &[u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
) -> anyhow::Result<Vec<u8>> {
    let fun_va = env.image_base.to_usize() + fun_rva;

    // @NOTE: Requires a new allocation, since capstone cannot borrow function code mutably.
    let mut fun_bytes = coff_data[fun_rva..fun_rva + fun_size].to_vec();

    let code = &coff_data[fun_rva..fun_rva + fun_size];
    let mut decoder = Decoder::with_ip(32, code, fun_va as u64, DecoderOptions::NONE);
    let mut ix = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut ix);

        let offset_in_fun = (ix.ip() - fun_va as u64) as usize + ix.len();

        match ix.flow_control() {
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::Call => {}
            _ => continue,
        }

        let target_va = match ix.op0_kind() {
            OpKind::NearBranch16 => ix.near_branch16() as u64,
            OpKind::NearBranch32 => ix.near_branch32() as u64,
            OpKind::NearBranch64 => unreachable!(),
            _ => continue,
        };

        let target_rva = target_va - u64::from(env.image_base);

        let internal_branch = (fun_rva..fun_rva + fun_size).contains(&(target_rva.to_usize()));
        if internal_branch {
            continue;
        }

        if ix.len() <= 4 {
            // Read data as code. Which is jump tables stored inline.
            continue;
        }

        let Some(overloads) = symbols.functions.get(&target_rva.to_usize()) else {
            // Read data as code. Which is jump tables stored inline.
            continue;
        };

        let overloads = overloads.as_slice();

        fun_bytes[offset_in_fun - 4..offset_in_fun].copy_from_slice(&0_u32.to_le_bytes());
        let old_reloc = relocs_rva.insert(
            fun_rva + offset_in_fun - 4,
            RelocKind::Function {
                overloads,
                encoding: RelocationEncoding::Relative,
            },
        );

        if let Some(old_reloc) = old_reloc {
            let RelocKind::Function {
                overloads: old_overloads,
                ..
            } = old_reloc
            else {
                unreachable!();
            };
            assert_eq!(overloads.as_ptr(), old_overloads.as_ptr());
        }
    }

    Ok(fun_bytes)
}

impl ObjectFile {
    fn add_relocation_at(
        &mut self,
        reloc_kind: RelocKind,
        reloc_offset: ObjectOffset,
        //
        matcher: &SymbolMatcher,
        coff_data: &[u8],
        relocs_rva: &BTreeMap<usize, RelocKind>,
        // Target RVAs already expanded on this pointer chain (cycle guard).
        visited: &mut HashSet<usize>,
        data_manifest: &DataManifest,
        target_materialization: TargetMaterialization,
    ) -> anyhow::Result<()> {
        let reloc_name = reloc_kind.get_name(matcher);
        let reloc_name = reloc_name.as_raw_string();

        let target_is_manifest_definition = match reloc_kind {
            RelocKind::Constant { target_rva, .. } | RelocKind::Static { target_rva, .. } => {
                data_manifest.owner_and_addend_for_rva(target_rva).is_some()
            }
            RelocKind::Function { .. } | RelocKind::ConstantString { .. } => false,
        };
        if target_materialization == TargetMaterialization::ReferenceOnly
            || target_is_manifest_definition
        {
            let encoding = match reloc_kind {
                RelocKind::Function { encoding, .. } => encoding,
                RelocKind::ConstantString { .. }
                | RelocKind::Constant { .. }
                | RelocKind::Static { .. } => RelocationEncoding::Absolute,
            };
            let symbol_reuse = if target_is_manifest_definition {
                SymbolReuse::ReuseIfDefined
            } else {
                SymbolReuse::AlwaysCreate
            };
            self.add_relocation(
                reloc_name,
                ObjectLocation::Extern,
                reloc_offset,
                encoding,
                symbol_reuse,
            )?;
            return Ok(());
        }

        match reloc_kind {
            RelocKind::Function {
                overloads: _,
                encoding,
            } => {
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern,
                    reloc_offset,
                    encoding,
                    SymbolReuse::AlwaysCreate,
                )?;
            }

            RelocKind::ConstantString { symbol: _, data } => {
                let const_offset_in_coff_rdata =
                    self.append_section_data(self.rdata_section_id, data, 0x00);

                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                    SymbolReuse::AlwaysCreate,
                )?;
            }

            RelocKind::Constant {
                symbol: _,
                target_rva,
            } => {
                let new_data =
                    bytemuck::pod_read_unaligned::<[u8; 4]>(&coff_data[target_rva..target_rva + 4]);
                let const_offset_in_coff_rdata =
                    self.append_section_data(self.rdata_section_id, &new_data, 0x00);
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                    SymbolReuse::AlwaysCreate,
                )?;

                // Cycle guard for self-referential RVAs.
                if let Some(reloc_kind) = relocs_rva.get(&target_rva) {
                    if visited.insert(target_rva) {
                        self.add_relocation_at(
                            *reloc_kind,
                            const_offset_in_coff_rdata,
                            matcher,
                            coff_data,
                            relocs_rva,
                            visited,
                            data_manifest,
                            TargetMaterialization::Materialize,
                        )?;
                    }
                }
            }

            RelocKind::Static {
                symbol: _,
                target_rva,
            } => {
                let new_data =
                    bytemuck::pod_read_unaligned::<[u8; 4]>(&coff_data[target_rva..target_rva + 4]);
                let static_offset_in_coff_data =
                    self.append_section_data(self.data_section_id, &new_data, 0x00);
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(static_offset_in_coff_data),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                    SymbolReuse::AlwaysCreate,
                )?;

                // Same cycle guard as the Constant arm above.
                if let Some(reloc_kind) = relocs_rva.get(&target_rva) {
                    if visited.insert(target_rva) {
                        self.add_relocation_at(
                            *reloc_kind,
                            static_offset_in_coff_data,
                            matcher,
                            coff_data,
                            relocs_rva,
                            visited,
                            data_manifest,
                            TargetMaterialization::Materialize,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    fn add_data_definition(
        &mut self,
        definition: DataDefinition,
        coff_data: &[u8],
    ) -> anyhow::Result<()> {
        let definition_end = definition
            .rva
            .checked_add(definition.size)
            .ok_or_else(|| anyhow::anyhow!("reviewed data definition extent overflows"))?;
        if definition_end > coff_data.len() {
            anyhow::bail!("reviewed data definition is outside mapped PE image");
        }
        let offset = match definition.storage {
            DataStorage::Data => ObjectOffset {
                offset: self.object.append_section_data(
                    self.data_section_id,
                    &coff_data[definition.rva..definition_end],
                    definition.alignment,
                ),
                section_id: self.data_section_id,
            },
            DataStorage::Rdata => ObjectOffset {
                offset: self.object.append_section_data(
                    self.rdata_section_id,
                    &coff_data[definition.rva..definition_end],
                    definition.alignment,
                ),
                section_id: self.rdata_section_id,
            },
            DataStorage::Bss => {
                let section_id = *self.bss_section_id.get_or_insert_with(|| {
                    self.object
                        .add_section(vec![], b".bss".into(), SectionKind::UninitializedData)
                });
                let offset = self.object.append_section_bss(
                    section_id,
                    definition.size.to_u64(),
                    definition.alignment,
                );
                ObjectOffset { offset, section_id }
            }
        };
        if let Some(expected) = definition.section_offset
            && offset.offset.to_usize() != expected
        {
            anyhow::bail!(
                "candidate data topology mismatch for {}: expected section offset {expected:#x}, emitted {:#x}",
                definition.symbol_name,
                offset.offset,
            );
        }
        if self
            .object
            .symbol_id(definition.symbol_name.as_bytes())
            .is_some()
        {
            anyhow::bail!(
                "duplicate PDB data symbol {} in owner object",
                definition.symbol_name
            );
        }
        self.object.add_symbol(object::write::Symbol {
            name: definition.symbol_name.as_bytes().to_vec(),
            value: offset.offset,
            size: definition.size.to_u64(),
            kind: object::SymbolKind::Data,
            scope: match definition.scope {
                DataScope::External => object::SymbolScope::Linkage,
                DataScope::Local => object::SymbolScope::Compilation,
            },
            weak: false,
            section: object::write::SymbolSection::Section(offset.section_id),
            flags: object::SymbolFlags::None,
        });
        Ok(())
    }

    fn add_data_relocations(
        &mut self,
        definition: DataDefinition,
        matcher: &SymbolMatcher,
        coff_data: &[u8],
        relocs_rva: &BTreeMap<usize, RelocKind>,
        data_manifest: &DataManifest,
    ) -> anyhow::Result<()> {
        let definition_end = definition.rva.checked_add(definition.size).unwrap();
        let symbol_id = self
            .object
            .symbol_id(definition.symbol_name.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("missing emitted PDB data symbol"))?;
        let symbol = self.object.symbol(symbol_id);
        let object::write::SymbolSection::Section(section_id) = symbol.section else {
            anyhow::bail!("emitted PDB data symbol has no output section");
        };
        let offset = ObjectOffset {
            offset: symbol.value,
            section_id,
        };
        let sites = relocs_rva.range(definition.rva..definition_end);
        if definition.storage == DataStorage::Bss && sites.clone().next().is_some() {
            anyhow::bail!("reviewed BSS definition contains a PE base relocation");
        }
        for (reloc_rva, reloc_kind) in sites {
            let mut visited = HashSet::new();
            self.add_relocation_at(
                *reloc_kind,
                offset + (*reloc_rva - definition.rva),
                matcher,
                coff_data,
                relocs_rva,
                &mut visited,
                data_manifest,
                TargetMaterialization::ReferenceOnly,
            )?;
        }
        Ok(())
    }
}

impl ObjectFile {
    fn append_section_data(
        &mut self,
        section_id: object::write::SectionId,
        data: &[u8],
        pad: u8,
    ) -> ObjectOffset {
        let offset = append_with_padding(&mut self.object, section_id, data, pad);
        ObjectOffset { offset, section_id }
    }

    fn add_relocation(
        &mut self,
        name: RawString,
        location: ObjectLocation,
        offset: ObjectOffset,
        encoding: RelocationEncoding,
        symbol_reuse: SymbolReuse,
    ) -> anyhow::Result<()> {
        let (value, kind, section) = match location {
            ObjectLocation::Extern => (
                0,
                object::SymbolKind::Unknown,
                object::write::SymbolSection::Undefined,
            ),
            ObjectLocation::Offset(ObjectOffset { offset, section_id }) => {
                let kind = if section_id == self.text_section_id {
                    object::SymbolKind::Text
                } else {
                    object::SymbolKind::Data
                };
                (
                    offset,
                    kind,
                    object::write::SymbolSection::Section(section_id),
                )
            }
        };

        let symbol = match symbol_reuse {
            SymbolReuse::ReuseIfDefined => {
                self.object.symbol_id(name.as_bytes()).unwrap_or_else(|| {
                    self.object.add_symbol(object::write::Symbol {
                        name: name.as_bytes().to_vec(),
                        value,
                        size: u64::MAX,
                        kind,
                        scope: object::SymbolScope::Linkage,
                        weak: false,
                        section,
                        flags: object::SymbolFlags::None,
                    })
                })
            }
            SymbolReuse::AlwaysCreate => self.object.add_symbol(object::write::Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size: u64::MAX,
                kind,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section,
                flags: object::SymbolFlags::None,
            }),
        };

        let (kind, addend) = match encoding {
            RelocationEncoding::Relative => (object::RelocationKind::Relative, -4),
            RelocationEncoding::Absolute => (object::RelocationKind::Absolute, 0),
        };

        self.object.add_relocation(
            offset.section_id,
            object::write::Relocation {
                offset: offset.offset,
                symbol,
                addend,
                flags: object::RelocationFlags::Generic {
                    kind,
                    encoding: object::RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )?;

        Ok(())
    }

    fn add_function(&mut self, name: RawString, body: &[u8]) -> ObjectOffset {
        let fun_offset_in_coff_text = self.append_section_data(self.text_section_id, body, 0x90);

        self.object.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: fun_offset_in_coff_text.offset,
            size: u64::MAX,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(fun_offset_in_coff_text.section_id),
            flags: object::SymbolFlags::None,
        });

        fun_offset_in_coff_text
    }
}

// Parse PDB symbols by iterating through symbol table and then through all modules

enum Name<'a> {
    Borrowed(RawString<'a>),
    Owned(Vec<u8>),
}

impl<'a> RelocKind<'a> {
    fn get_name(self, matcher: &SymbolMatcher) -> Name<'a> {
        match self {
            Self::Function { overloads, .. } => {
                Name::Borrowed(matcher.pick(overloads, canonical_name(overloads)))
            }
            Self::ConstantString { symbol, data } => {
                let reloc_name = get_constant_name(symbol, data);
                Name::Owned(reloc_name)
            }
            Self::Constant {
                symbol: reloc_name,
                target_rva: _,
            } => Name::Borrowed(reloc_name),
            Self::Static {
                symbol: reloc_name,
                target_rva: _,
            } => Name::Borrowed(reloc_name),
        }
    }
}

impl Name<'_> {
    fn as_raw_string(&self) -> RawString<'_> {
        match self {
            Self::Owned(name) => RawString::from(name.as_slice()),
            Self::Borrowed(name) => *name,
        }
    }
}

impl std::ops::Add<usize> for ObjectOffset {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Self {
            offset: self.offset + rhs.to_u64(),
            section_id: self.section_id,
        }
    }
}

// Always pads to 4
fn append_with_padding(
    object: &mut object::write::Object,
    section_id: object::write::SectionId,
    data: &[u8],
    pad: u8,
) -> u64 {
    let offset = object.append_section_data(section_id, data, 1);

    // sushi@NOTE: `object` crate doesn't(?) allow specifying auxiliary symbols.
    // Because of that 1-3 bytes of garbage are generated which objdiff doesn't like.
    // We replace those bytes with `nop`s and pad all of the functions ourselves,
    // which fixes the problem, but this is a hack, which needs to be fixed at some point.
    let padding: &[u8] = match 4 - data.len() % 4 {
        1 => &[pad],
        2 => &[pad, pad],
        3 => &[pad, pad, pad],
        _ => &[],
    };
    if !padding.is_empty() {
        _ = object.append_section_data(section_id, padding, 1);
    }

    offset
}

//
//
//

fn get_constant_name(symbol: RawString, data: &[u8]) -> Vec<u8> {
    match () {
        () if symbol.as_bytes().starts_with(b"??_C@_0") => data
            .iter()
            .copied()
            .map(|c| match c.is_ascii_alphanumeric() {
                true => c,
                false => b'_',
            })
            .collect::<Vec<_>>(),
        () if symbol.as_bytes().starts_with(b"??_C@_1") => data
            .windows(2)
            .map(|c| match c[0] == b'\0' && c[1].is_ascii_alphanumeric() {
                true => c[1],
                false => b'_',
            })
            .collect::<Vec<_>>(),
        () => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(scope: DataScope, section_offset: usize) -> DataDefinition {
        DataDefinition {
            symbol_name: RawString::from(&b"fixture"[..]),
            object: b"fixture.c",
            rva: 0,
            size: 4,
            storage: DataStorage::Data,
            alignment: 4,
            section_offset: Some(section_offset),
            scope,
        }
    }

    #[test]
    fn emits_reviewed_compilation_scope() {
        let mut object = ObjectFile::empty(false);
        object
            .add_data_definition(definition(DataScope::Local, 0), &[1, 2, 3, 4])
            .unwrap();
        let symbol_id = object.object.symbol_id(b"fixture").unwrap();
        assert_eq!(
            object.object.symbol(symbol_id).scope,
            object::SymbolScope::Compilation
        );
    }

    #[test]
    fn rejects_a_candidate_offset_that_was_not_emitted() {
        let mut object = ObjectFile::empty(false);
        let error = object
            .add_data_definition(definition(DataScope::External, 4), &[1, 2, 3, 4])
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected section offset 0x4, emitted 0x0"));
    }
}
