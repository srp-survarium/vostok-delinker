use crate::Env;
use crate::contribution_manifest::ContributionStorage;
use crate::data_manifest::{DataDefinition, DataManifest, DataScope, DataStorage};
use crate::data_section_manifest::{DataSection, DataSectionManifest, SectionStorage};
use crate::pdb_symbols::PdbSymbols;
use crate::reloc_alias_manifest::{RelocAliasManifest, RelocAliasObservations};
use crate::relocs::RelocKind;
use crate::symbol_matcher::{SymbolMatcher, canonical_name};
use crate::utils::{ToU64, ToUsize, contains, leak};

use std::collections::{BTreeMap, HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use pdb2::{FallibleIterator, RawString};

use object::write::SymbolId;
use object::{ComdatKind, SectionFlags, SectionKind};

pub struct ObjectFiles<'a> {
    pub objects: HashMap<&'a [u8], ObjectFile>,
}

pub struct ObjectFile {
    pub object: object::write::Object<'static>,
    pub data_section_id: object::write::SectionId,
    pub rdata_section_id: object::write::SectionId,
    pub bss_section_id: Option<object::write::SectionId>,
    pub text_section_id: object::write::SectionId,
    pub topology_sections: HashMap<usize, TopologySection>,
    pub data_comdats: Vec<(usize, object::write::SectionId, u8)>,
    pub comdat_leaders: HashMap<usize, SymbolId>,
    pub symbols: HashMap<Vec<u8>, SymbolId>,
    pub definition_offsets: HashMap<Vec<u8>, ObjectOffset>,
    pub definition_ranges: HashMap<usize, Vec<(usize, usize)>>,
}

#[derive(Copy, Clone)]
pub struct TopologySection {
    section_id: object::write::SectionId,
    storage: Option<SectionStorage>,
    rva: Option<usize>,
    size: usize,
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
        data_section_manifest: &DataSectionManifest,
        reloc_aliases: &RelocAliasManifest,
        observed_aliases: &mut RelocAliasObservations,
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self {
            objects: HashMap::new(),
        };

        let mut sections_by_object = HashMap::<&[u8], Vec<DataSection>>::new();
        for section in data_section_manifest.sections() {
            sections_by_object
                .entry(section.object)
                .or_default()
                .push(*section);
        }
        for (object, sections) in sections_by_object {
            this.objects.insert(
                object,
                ObjectFile::with_sections(
                    &sections,
                    env.rdata,
                    env.data,
                    coff_data,
                    pad_empty_rdata,
                )?,
            );
        }

        for definition in data_manifest.definitions() {
            let definition_end = definition.rva.checked_add(definition.size).unwrap();
            let section = match definition.storage {
                DataStorage::Rdata => env.rdata,
                DataStorage::Data | DataStorage::Bss => env.data,
            };
            if !definition.provisional
                && (definition.rva < section.rva || definition_end > section.rva + section.size)
            {
                anyhow::bail!("data manifest storage does not match the PE section");
            }
            let object_file = this
                .objects
                .entry(definition.object)
                .or_insert_with(|| ObjectFile::empty(pad_empty_rdata));
            object_file.add_data_definition(*definition, coff_data)?;
        }
        for object_file in this.objects.values_mut() {
            object_file.add_topology_section_relocations(
                matcher,
                coff_data,
                &relocs_rva,
                data_manifest,
            )?;
        }
        for definition in data_manifest.definitions() {
            let object_file = this.objects.get_mut(definition.object).unwrap();
            if !object_file.definition_uses_affine_topology(*definition) {
                object_file.add_legacy_data_relocations(
                    *definition,
                    matcher,
                    coff_data,
                    &relocs_rva,
                    data_manifest,
                )?;
            }
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
                    reloc_aliases,
                    observed_aliases,
                )?;

                let object_file = this
                    .objects
                    .entry(filename)
                    .or_insert_with(|| ObjectFile::empty(pad_empty_rdata));

                let overloads = symbols
                    .functions
                    .get(&fun_rva)
                    .map(Vec::as_slice)
                    .unwrap_or_else(|| std::slice::from_ref(&fun_name));
                let fun_name = matcher.pick(overloads, canonical_name(overloads));

                let fun_offset_in_coff_text =
                    object_file.add_function(fun_name, overloads, &fun_bytes);

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
                        true,
                    )?;
                }
            }
        }

        Ok(this)
    }

    pub fn write(self, base: &std::path::Path) -> anyhow::Result<()> {
        let base_len = base.as_os_str().as_encoded_bytes().len();
        let mut path = base.to_path_buf();

        for (prefix, mut object_file) in self.objects {
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
            object_file.finish_data_comdats()?;
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
            topology_sections: HashMap::new(),
            data_comdats: Vec::new(),
            comdat_leaders: HashMap::new(),
            symbols: HashMap::new(),
            definition_offsets: HashMap::new(),
            definition_ranges: HashMap::new(),
        }
    }

    fn with_sections(
        sections: &[DataSection],
        rdata: crate::SecInfo,
        data: crate::SecInfo,
        coff_data: &[u8],
        pad_rdata: bool,
    ) -> anyhow::Result<Self> {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Coff,
            object::Architecture::I386,
            object::Endianness::Little,
        );
        object.set_mangling(object::write::Mangling::None);
        let mut topology_sections = HashMap::new();
        let mut data_comdats = Vec::new();
        let mut data_section_id = None;
        let mut rdata_section_id = None;
        let mut bss_section_id = None;
        let mut text_section_id = None;
        for section in sections {
            let kind = match section.storage {
                Some(SectionStorage::Data) => SectionKind::Data,
                Some(SectionStorage::Rdata) => SectionKind::ReadOnlyData,
                Some(SectionStorage::Bss) => SectionKind::UninitializedData,
                None if section.name == b".text" => SectionKind::Text,
                None => SectionKind::Other,
            };
            let id = object.add_section(vec![], section.name.to_vec(), kind);
            object.section_mut(id).flags = SectionFlags::Coff {
                characteristics: section.characteristics
                    & !(object::pe::IMAGE_SCN_ALIGN_MASK | object::pe::IMAGE_SCN_LNK_COMDAT),
            };
            match (section.storage, section.rva) {
                (Some(storage), Some(rva)) => {
                    let end = rva.checked_add(section.size).ok_or_else(|| {
                        anyhow::anyhow!("candidate data section extent overflows")
                    })?;
                    let pe_section = match storage {
                        SectionStorage::Rdata => rdata,
                        SectionStorage::Data | SectionStorage::Bss => data,
                    };
                    if rva < pe_section.rva || end > pe_section.rva + pe_section.size {
                        anyhow::bail!(
                            "candidate data section {} storage does not match the PE section",
                            section.ordinal
                        );
                    }
                    match storage {
                        SectionStorage::Bss => {
                            object.append_section_bss(id, section.size as u64, section.alignment);
                        }
                        SectionStorage::Data | SectionStorage::Rdata => {
                            if end > coff_data.len() {
                                anyhow::bail!(
                                    "candidate data section {} is outside mapped PE image",
                                    section.ordinal
                                );
                            }
                            object.set_section_data(
                                id,
                                coff_data[rva..end].to_vec(),
                                section.alignment,
                            );
                        }
                    }
                }
                (Some(SectionStorage::Bss), None) => {
                    object.append_section_bss(id, section.size as u64, section.alignment);
                }
                (Some(SectionStorage::Data | SectionStorage::Rdata), None) => {
                    // A non-affine section retains the candidate COFF shape.
                    // Reviewed definitions copy their independent retail payloads
                    // into this deterministic zero-filled buffer below.
                    object.set_section_data(id, vec![0; section.size], section.alignment);
                }
                (None, None) => object.set_section_data(id, Vec::new(), section.alignment),
                (None, Some(_)) => unreachable!("section manifest validates assigned RVAs"),
            }
            object.section_symbol(id);
            topology_sections.insert(
                section.ordinal,
                TopologySection {
                    section_id: id,
                    storage: section.storage,
                    rva: section.rva,
                    size: section.size,
                },
            );
            match section.storage {
                Some(SectionStorage::Data) if data_section_id.is_none() => {
                    data_section_id = Some(id)
                }
                Some(SectionStorage::Rdata) if rdata_section_id.is_none() => {
                    rdata_section_id = Some(id)
                }
                Some(SectionStorage::Bss) if bss_section_id.is_none() => bss_section_id = Some(id),
                None if section.name == b".text" && text_section_id.is_none() => {
                    text_section_id = Some(id)
                }
                _ => {}
            }
            if section.storage.is_some() && section.comdat_selection != 0 {
                data_comdats.push((section.ordinal, id, section.comdat_selection));
            }
        }
        let data_section_id = data_section_id
            .unwrap_or_else(|| object.add_section(vec![], b".data".into(), SectionKind::Data));
        let rdata_section_id = rdata_section_id.unwrap_or_else(|| {
            object.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData)
        });
        let text_section_id = text_section_id
            .unwrap_or_else(|| object.add_section(vec![], b".text".into(), SectionKind::Text));
        if pad_rdata {
            object.append_section_data(rdata_section_id, &0_u32.to_le_bytes(), 4);
        }
        Ok(Self {
            object,
            data_section_id,
            rdata_section_id,
            bss_section_id,
            text_section_id,
            topology_sections,
            data_comdats,
            comdat_leaders: HashMap::new(),
            symbols: HashMap::new(),
            definition_offsets: HashMap::new(),
            definition_ranges: HashMap::new(),
        })
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
    reloc_aliases: &RelocAliasManifest,
    observed_aliases: &mut RelocAliasObservations,
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
        let reloc_rva = fun_rva + offset_in_fun - 4;
        let symbol = reloc_aliases.resolve_function_alias(
            fun_rva,
            target_rva.to_usize(),
            reloc_rva,
            overloads,
            observed_aliases,
        )?;

        fun_bytes[offset_in_fun - 4..offset_in_fun].copy_from_slice(&0_u32.to_le_bytes());
        let old_reloc = relocs_rva.insert(
            reloc_rva,
            // A decoded call/jmp/jcc target -> PC-relative branch.
            RelocKind::Function {
                overloads,
                symbol,
                relative: true,
            },
        );

        if let Some(old_reloc) = old_reloc {
            let RelocKind::Function {
                overloads: old_overloads,
                symbol: old_symbol,
                ..
            } = old_reloc
            else {
                unreachable!();
            };
            assert_eq!(overloads.as_ptr(), old_overloads.as_ptr());
            assert_eq!(symbol, old_symbol);
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
        materialize_target: bool,
    ) -> anyhow::Result<()> {
        let reloc_name = reloc_kind.get_name(matcher);
        let reloc_name = reloc_name.as_raw_string();

        if !materialize_target || data_manifest.contains_name(reloc_name.as_bytes()) {
            let relative = match reloc_kind {
                RelocKind::Function { relative, .. } => relative,
                _ => false,
            };
            self.add_relocation(reloc_name, ObjectLocation::Extern, reloc_offset, relative)?;
            return Ok(());
        }

        match reloc_kind {
            RelocKind::Function {
                overloads: _,
                symbol: _,
                relative,
            } => {
                self.add_relocation(reloc_name, ObjectLocation::Extern, reloc_offset, relative)?;
            }

            RelocKind::ConstantString { symbol: _, data } => {
                let const_offset_in_coff_rdata =
                    self.append_section_data(self.rdata_section_id, data, 0x00);

                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                    false,
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
                    false,
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
                            true,
                        )?;
                    }
                }
            }

            RelocKind::Static {
                symbol: _,
                target_rva,
                storage,
            } => {
                let static_offset_in_coff_data = if storage == ContributionStorage::Bss {
                    let section_id = *self.bss_section_id.get_or_insert_with(|| {
                        self.object.add_section(
                            vec![],
                            b".bss".into(),
                            SectionKind::UninitializedData,
                        )
                    });
                    ObjectOffset {
                        offset: self.object.append_section_bss(section_id, 4, 1),
                        section_id,
                    }
                } else {
                    let new_data = bytemuck::pod_read_unaligned::<[u8; 4]>(
                        &coff_data[target_rva..target_rva + 4],
                    );
                    self.append_section_data(self.data_section_id, &new_data, 0x00)
                };
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(static_offset_in_coff_data),
                    reloc_offset,
                    false,
                )?;

                // Same cycle guard as the Constant arm above.
                if storage != ContributionStorage::Bss {
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
                                true,
                            )?;
                        }
                    }
                }
            }

            RelocKind::Import { symbol: _ } => {
                self.add_relocation(reloc_name, ObjectLocation::Extern, reloc_offset, false)?;
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
        let topology_section =
            definition
                .section_ordinal
                .map(|ordinal| {
                    self.topology_sections
                .get(&ordinal)
                .copied()
                .ok_or_else(|| anyhow::anyhow!(
                    "reviewed data definition references absent section ordinal {ordinal}"))
                })
                .transpose()?;
        let expected_storage = match definition.storage {
            DataStorage::Data => SectionStorage::Data,
            DataStorage::Rdata => SectionStorage::Rdata,
            DataStorage::Bss => SectionStorage::Bss,
        };
        if let Some(section) = topology_section {
            if section.storage != Some(expected_storage) {
                anyhow::bail!("reviewed data definition storage disagrees with section manifest");
            }
            let section_offset = definition.section_offset.unwrap();
            let definition_end = section_offset
                .checked_add(definition.size)
                .ok_or_else(|| anyhow::anyhow!("reviewed data section-local extent overflows"))?;
            if definition_end > section.size {
                anyhow::bail!("reviewed data definition exceeds its assigned section");
            }
            if let Some(section_rva) = section.rva {
                let expected_rva = section_rva
                    .checked_add(section_offset)
                    .ok_or_else(|| anyhow::anyhow!("reviewed data section placement overflows"))?;
                if definition.rva != expected_rva {
                    anyhow::bail!(
                        "reviewed data definition RVA disagrees with section placement: expected {expected_rva:#x}, got {:#x}",
                        definition.rva
                    );
                }
            }
            let ranges = self
                .definition_ranges
                .entry(definition.section_ordinal.unwrap())
                .or_default();
            if ranges
                .iter()
                .any(|(start, end)| section_offset < *end && *start < definition_end)
            {
                anyhow::bail!("reviewed data definitions overlap in their candidate section");
            }
            ranges.push((section_offset, definition_end));

            if section.rva.is_none() && definition.storage != DataStorage::Bss {
                self.object.section_mut(section.section_id).data_mut()
                    [section_offset..definition_end]
                    .copy_from_slice(&coff_data[definition.rva..definition.rva + definition.size]);
            }
        }
        let offset = if let Some(section) = topology_section {
            ObjectOffset {
                offset: definition.section_offset.unwrap().to_u64(),
                section_id: section.section_id,
            }
        } else {
            match definition.storage {
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
                        self.object.add_section(
                            vec![],
                            b".bss".into(),
                            SectionKind::UninitializedData,
                        )
                    });
                    let offset = self.object.append_section_bss(
                        section_id,
                        definition.size.to_u64(),
                        definition.alignment,
                    );
                    ObjectOffset { offset, section_id }
                }
            }
        };
        if let Some(expected) = definition.section_offset {
            if offset.offset.to_usize() != expected {
                anyhow::bail!(
                    "candidate data topology mismatch for {}: expected section offset {expected:#x}, emitted {:#x}",
                    definition.name,
                    offset.offset,
                );
            }
        }
        let symbol = self.object.add_symbol(object::write::Symbol {
            name: definition.name.as_bytes().to_vec(),
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
        if let Some(ordinal) = definition.section_ordinal {
            if definition.section_offset == Some(0) && definition.scope == DataScope::External {
                self.comdat_leaders.entry(ordinal).or_insert(symbol);
            }
        }
        if self
            .symbols
            .insert(definition.name.as_bytes().to_vec(), symbol)
            .is_some()
        {
            anyhow::bail!("duplicate reviewed data definition in owner object");
        }
        self.definition_offsets
            .insert(definition.name.as_bytes().to_vec(), offset);
        Ok(())
    }

    fn finish_data_comdats(&mut self) -> anyhow::Result<()> {
        for (ordinal, section, selection) in self.data_comdats.clone() {
            let leader = self.comdat_leaders.get(&ordinal).copied().ok_or_else(|| {
                anyhow::anyhow!(
                    "candidate data COMDAT section {ordinal} has no external offset-zero leader"
                )
            })?;
            let kind = match selection {
                1 => ComdatKind::NoDuplicates,
                2 => ComdatKind::Any,
                3 => ComdatKind::SameSize,
                4 => ComdatKind::ExactMatch,
                6 => ComdatKind::Largest,
                7 => ComdatKind::Newest,
                5 => anyhow::bail!(
                    "associative data COMDAT section {ordinal} requires a leader group"
                ),
                value => {
                    anyhow::bail!("unsupported data COMDAT selection {value} in section {ordinal}")
                }
            };
            self.object.add_comdat(object::write::Comdat {
                kind,
                symbol: leader,
                sections: vec![section],
            });
        }
        Ok(())
    }

    fn definition_uses_affine_topology(&self, definition: DataDefinition) -> bool {
        definition
            .section_ordinal
            .and_then(|ordinal| self.topology_sections.get(&ordinal))
            .is_some_and(|section| section.rva.is_some())
    }

    fn add_topology_section_relocations(
        &mut self,
        matcher: &SymbolMatcher,
        coff_data: &[u8],
        relocs_rva: &BTreeMap<usize, RelocKind>,
        data_manifest: &DataManifest,
    ) -> anyhow::Result<()> {
        let sections = self
            .topology_sections
            .values()
            .copied()
            .filter(|section| section.rva.is_some())
            .collect::<Vec<_>>();
        for section in sections {
            let rva = section.rva.unwrap();
            let end = rva.checked_add(section.size).unwrap();
            let sites = relocs_rva.range(rva..end);
            if section.storage == Some(SectionStorage::Bss) && sites.clone().next().is_some() {
                anyhow::bail!("candidate BSS section contains a PE base relocation");
            }
            for (reloc_rva, reloc_kind) in sites {
                let mut visited = HashSet::new();
                self.add_relocation_at(
                    *reloc_kind,
                    ObjectOffset {
                        offset: (*reloc_rva - rva).to_u64(),
                        section_id: section.section_id,
                    },
                    matcher,
                    coff_data,
                    relocs_rva,
                    &mut visited,
                    data_manifest,
                    false,
                )?;
            }
        }
        Ok(())
    }

    fn add_legacy_data_relocations(
        &mut self,
        definition: DataDefinition,
        matcher: &SymbolMatcher,
        coff_data: &[u8],
        relocs_rva: &BTreeMap<usize, RelocKind>,
        data_manifest: &DataManifest,
    ) -> anyhow::Result<()> {
        let definition_end = definition.rva.checked_add(definition.size).unwrap();
        let offset = *self
            .definition_offsets
            .get(definition.name.as_bytes())
            .unwrap();
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
                false,
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
        // PC-relative branch (call/jmp/jcc) vs absolute address operand.
        relative: bool,
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

        let symbol = if let Some(symbol) = self.symbols.get(name.as_bytes()) {
            *symbol
        } else {
            let name = name.as_bytes().to_vec();
            let symbol = self.object.add_symbol(object::write::Symbol {
                name: name.clone(),
                value,
                size: u64::MAX,
                kind,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section,
                flags: object::SymbolFlags::None,
            });
            self.symbols.insert(name, symbol);
            symbol
        };

        // A relative branch's operand is the displacement from the END of the
        // 4-byte field, so it carries addend -4; an absolute operand (DIR32)
        // holds the symbol address directly (addend 0). cl.exe emits DIR32 for
        // every non-branch reference, so emitting REL32 there made objdiff flag
        // an arg mismatch even when the target symbol name matched.
        let (kind, addend) = if relative {
            (object::RelocationKind::Relative, -4)
        } else {
            (object::RelocationKind::Absolute, 0)
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

    fn add_function(
        &mut self,
        name: RawString,
        aliases: &[RawString],
        body: &[u8],
    ) -> ObjectOffset {
        let fun_offset_in_coff_text = self.append_section_data(self.text_section_id, body, 0x90);

        let mut names = vec![name];
        for alias in aliases {
            if !names
                .iter()
                .any(|existing| existing.as_bytes() == alias.as_bytes())
            {
                names.push(*alias);
            }
        }
        for name in names {
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
        }

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
            Self::Function {
                overloads, symbol, ..
            } => Name::Borrowed(
                symbol.unwrap_or_else(|| matcher.pick(overloads, canonical_name(overloads))),
            ),
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
                storage: _,
            } => Name::Borrowed(reloc_name),
            Self::Import { symbol } => Name::Borrowed(symbol),
        }
    }

    #[cfg(test)]
    fn recovered_data_storage(self) -> Option<DataStorage> {
        match self {
            Self::ConstantString { .. } | Self::Constant { .. } => Some(DataStorage::Rdata),
            Self::Static {
                storage: ContributionStorage::Data,
                ..
            } => Some(DataStorage::Data),
            Self::Static {
                storage: ContributionStorage::Bss,
                ..
            } => Some(DataStorage::Bss),
            Self::Import { .. } => None,
            _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use object::{Object as _, ObjectComdat as _, ObjectSection as _, ObjectSymbol as _};

    #[test]
    fn topology_emits_distinct_data_sections_and_comdat_auxiliary_record() {
        let sections = [
            DataSection {
                object: b"BASE\\Midi.c",
                ordinal: 1,
                name: b".drectve",
                rva: None,
                size: 0,
                alignment: 1,
                characteristics: 0x0010_0a00,
                comdat_selection: 0,
                associative_ordinal: None,
                storage: None,
            },
            DataSection {
                object: b"BASE\\Midi.c",
                ordinal: 2,
                name: b".data",
                rva: Some(0x10),
                size: 4,
                alignment: 8,
                characteristics: 0xc040_0040,
                comdat_selection: 0,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
            DataSection {
                object: b"BASE\\Midi.c",
                ordinal: 3,
                name: b".data",
                rva: Some(0x20),
                size: 4,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: 2,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
        ];
        let mut image = vec![0_u8; 0x30];
        image[0x10..0x14].copy_from_slice(b"main");
        image[0x20..0x24].copy_from_slice(b"lit\0");
        let rdata = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 2,
            data: &[],
        };
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let mut output = ObjectFile::with_sections(&sections, rdata, data, &image, false).unwrap();
        for definition in [
            DataDefinition {
                name: b"main_data".as_slice().into(),
                object: b"BASE\\Midi.c",
                rva: 0x10,
                size: 4,
                storage: DataStorage::Data,
                alignment: 8,
                section_ordinal: Some(2),
                section_offset: Some(0),
                scope: DataScope::External,
                provisional: false,
                address_authoritative: true,
            },
            DataDefinition {
                name: b"??_C@fixture".as_slice().into(),
                object: b"BASE\\Midi.c",
                rva: 0x20,
                size: 4,
                storage: DataStorage::Data,
                alignment: 4,
                section_ordinal: Some(3),
                section_offset: Some(0),
                scope: DataScope::External,
                provisional: false,
                address_authoritative: true,
            },
        ] {
            output.add_data_definition(definition, &image).unwrap();
        }
        output.finish_data_comdats().unwrap();

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let parsed_sections = object.sections().collect::<Vec<_>>();
        let section_names = parsed_sections
            .iter()
            .map(|section| section.name().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(&section_names[..3], [".drectve", ".data", ".data"]);
        assert_eq!(parsed_sections[1].data().unwrap(), b"main");
        assert_eq!(parsed_sections[2].data().unwrap(), b"lit\0");
        assert!(matches!(
            parsed_sections[2].flags(),
            SectionFlags::Coff { characteristics }
                if characteristics & object::pe::IMAGE_SCN_LNK_COMDAT != 0
                    && characteristics & object::pe::IMAGE_SCN_ALIGN_MASK
                        == object::pe::IMAGE_SCN_ALIGN_4BYTES
        ));
        let definitions = object
            .symbols()
            .filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.section_index())))
            .collect::<Vec<_>>();
        assert!(definitions.iter().any(|(name, section)| {
            name == "main_data" && *section == Some(object::SectionIndex(2))
        }));
        assert!(definitions.iter().any(|(name, section)| {
            name == "??_C@fixture" && *section == Some(object::SectionIndex(3))
        }));
        let comdats = object.comdats().collect::<Vec<_>>();
        assert_eq!(comdats.len(), 1);
        assert_eq!(comdats[0].kind(), ComdatKind::Any);
        assert_eq!(
            object
                .symbol_by_index(comdats[0].symbol())
                .unwrap()
                .name()
                .unwrap(),
            "??_C@fixture"
        );
    }

    #[test]
    fn non_affine_topology_copies_reviewed_payloads_and_relocations_by_definition() {
        let sections = [DataSection {
            object: b"SOURCE\\a.c",
            ordinal: 1,
            name: b".data",
            rva: None,
            size: 0x10,
            alignment: 8,
            characteristics: 0xc040_0040,
            comdat_selection: 0,
            associative_ordinal: None,
            storage: Some(SectionStorage::Data),
        }];
        let mut image = [0_u8; 0x50];
        image[0x10..0x14].copy_from_slice(b"left");
        image[0x30..0x34].copy_from_slice(b"rght");
        image[0x34..0x38].copy_from_slice(&3_u32.to_le_bytes());
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 2,
            data: &[],
        };
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let definitions = [
            DataDefinition {
                name: b"left".as_slice().into(),
                object: b"SOURCE\\a.c",
                rva: 0x10,
                size: 4,
                storage: DataStorage::Data,
                alignment: 4,
                section_ordinal: Some(1),
                section_offset: Some(0),
                scope: DataScope::External,
                provisional: false,
                address_authoritative: true,
            },
            DataDefinition {
                name: b"right".as_slice().into(),
                object: b"SOURCE\\a.c",
                rva: 0x30,
                size: 8,
                storage: DataStorage::Data,
                alignment: 4,
                section_ordinal: Some(1),
                section_offset: Some(8),
                scope: DataScope::External,
                provisional: false,
                address_authoritative: true,
            },
        ];
        let mut output = ObjectFile::with_sections(&sections, empty, data, &image, false).unwrap();
        for definition in definitions {
            output.add_data_definition(definition, &image).unwrap();
        }

        let mut relocs = BTreeMap::new();
        relocs.insert(
            0x34,
            RelocKind::Static {
                symbol: b"external".as_slice().into(),
                target_rva: 0x40,
                storage: ContributionStorage::Data,
            },
        );
        output
            .add_topology_section_relocations(
                &SymbolMatcher::off(),
                &image,
                &relocs,
                &DataManifest::default(),
            )
            .unwrap();
        for definition in definitions {
            assert!(!output.definition_uses_affine_topology(definition));
            output
                .add_legacy_data_relocations(
                    definition,
                    &SymbolMatcher::off(),
                    &image,
                    &relocs,
                    &DataManifest::default(),
                )
                .unwrap();
        }

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let section = object.section_by_name(".data").unwrap();
        assert_eq!(section.data().unwrap(), b"left\0\0\0\0rght\x03\0\0\0");
        let relocation = section.relocations().next().unwrap();
        assert_eq!(relocation.0, 0xc);
        let object::RelocationTarget::Symbol(symbol) = relocation.1.target() else {
            panic!("data relocation must target an external symbol");
        };
        assert_eq!(
            object.symbol_by_index(symbol).unwrap().name(),
            Ok("external")
        );
    }

    #[test]
    fn non_affine_topology_rejects_candidate_offset_overlaps() {
        let sections = [DataSection {
            object: b"SOURCE\\a.c",
            ordinal: 1,
            name: b".data",
            rva: None,
            size: 8,
            alignment: 4,
            characteristics: 0xc030_0040,
            comdat_selection: 0,
            associative_ordinal: None,
            storage: Some(SectionStorage::Data),
        }];
        let image = [0_u8; 0x20];
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 2,
            data: &[],
        };
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let mut output = ObjectFile::with_sections(&sections, empty, data, &image, false).unwrap();
        let definition = |name: &'static [u8], rva, offset| DataDefinition {
            name: RawString::from(name),
            object: b"SOURCE\\a.c",
            rva,
            size: 4,
            storage: DataStorage::Data,
            alignment: 1,
            section_ordinal: Some(1),
            section_offset: Some(offset),
            scope: DataScope::Local,
            provisional: false,
            address_authoritative: true,
        };
        output
            .add_data_definition(definition(b"first", 0x10, 0), &image)
            .unwrap();
        let error = output
            .add_data_definition(definition(b"second", 0x14, 2), &image)
            .unwrap_err();
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn topology_replays_relocations_for_each_folded_comdat_section() {
        let sections = [
            DataSection {
                object: b"SOURCE\\a.c",
                ordinal: 1,
                name: b".data",
                rva: Some(0x10),
                size: 8,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: 2,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
            DataSection {
                object: b"SOURCE\\a.c",
                ordinal: 2,
                name: b".data",
                rva: Some(0x10),
                size: 8,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: 2,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
        ];
        let image = [0_u8; 0x20];
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 2,
            data: &[],
        };
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let mut output = ObjectFile::with_sections(&sections, empty, data, &image, false).unwrap();
        for (name, ordinal) in [(b"leader_a".as_slice(), 1), (b"leader_b".as_slice(), 2)] {
            output
                .add_data_definition(
                    DataDefinition {
                        name: name.into(),
                        object: b"SOURCE\\a.c",
                        rva: 0x10,
                        size: 4,
                        storage: DataStorage::Data,
                        alignment: 4,
                        section_ordinal: Some(ordinal),
                        section_offset: Some(0),
                        scope: DataScope::External,
                        provisional: true,
                        address_authoritative: false,
                    },
                    &image,
                )
                .unwrap();
        }
        assert_eq!(output.definition_offsets.len(), 2);

        let mut relocs = BTreeMap::new();
        relocs.insert(
            0x14,
            RelocKind::Static {
                symbol: b"external".as_slice().into(),
                target_rva: 0x18,
                storage: ContributionStorage::Data,
            },
        );
        output
            .add_topology_section_relocations(
                &SymbolMatcher::off(),
                &image,
                &relocs,
                &DataManifest::default(),
            )
            .unwrap();
        output.finish_data_comdats().unwrap();

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let data_sections = object
            .sections()
            .filter(|section| section.name() == Ok(".data"))
            .collect::<Vec<_>>();
        assert_eq!(data_sections.len(), 2);
        for section in data_sections {
            let relocations = section.relocations().collect::<Vec<_>>();
            assert_eq!(relocations.len(), 1);
            assert_eq!(relocations[0].0, 4);
            let object::RelocationTarget::Symbol(symbol) = relocations[0].1.target() else {
                panic!("data relocation must target an external symbol");
            };
            assert_eq!(
                object.symbol_by_index(symbol).unwrap().name(),
                Ok("external")
            );
        }
    }

    #[test]
    fn topology_rejects_definition_beyond_assigned_section() {
        let sections = [DataSection {
            object: b"SOURCE\\a.c",
            ordinal: 1,
            name: b".data",
            rva: Some(0x10),
            size: 4,
            alignment: 4,
            characteristics: 0xc030_0040,
            comdat_selection: 0,
            associative_ordinal: None,
            storage: Some(SectionStorage::Data),
        }];
        let image = [0_u8; 0x20];
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 2,
            data: &[],
        };
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let mut output = ObjectFile::with_sections(&sections, empty, data, &image, false).unwrap();
        let error = output
            .add_data_definition(
                DataDefinition {
                    name: b"too_large".as_slice().into(),
                    object: b"SOURCE\\a.c",
                    rva: 0x10,
                    size: 5,
                    storage: DataStorage::Data,
                    alignment: 4,
                    section_ordinal: Some(1),
                    section_offset: Some(0),
                    scope: DataScope::External,
                    provisional: true,
                    address_authoritative: false,
                },
                &image,
            )
            .unwrap_err();
        assert!(error.to_string().contains("exceeds its assigned section"));
    }

    #[test]
    fn permissive_pdb_recovery_preserves_all_data_storage_classes() {
        let symbol: RawString<'static> = b"fixture".as_slice().into();
        let rdata = RelocKind::Constant {
            symbol,
            target_rva: 0x100,
        };
        let data = RelocKind::Static {
            symbol,
            target_rva: 0x200,
            storage: ContributionStorage::Data,
        };
        let bss = RelocKind::Static {
            symbol,
            target_rva: 0x300,
            storage: ContributionStorage::Bss,
        };
        let import = RelocKind::Import { symbol };
        assert_eq!(rdata.recovered_data_storage(), Some(DataStorage::Rdata));
        assert_eq!(data.recovered_data_storage(), Some(DataStorage::Data));
        assert_eq!(bss.recovered_data_storage(), Some(DataStorage::Bss));
        assert_eq!(import.recovered_data_storage(), None);
    }

    #[test]
    fn relocations_reuse_one_undefined_external_symbol() {
        let mut object = ObjectFile::empty(false);
        let bytes = [0_u8; 8];
        let offset = object.append_section_data(object.text_section_id, &bytes, 0x90);
        let name: RawString<'static> = b"external".as_slice().into();

        object
            .add_relocation(name, ObjectLocation::Extern, offset, false)
            .unwrap();
        object
            .add_relocation(name, ObjectLocation::Extern, offset + 4, false)
            .unwrap();

        assert_eq!(object.symbols.len(), 1);
        assert!(object.symbols.contains_key(b"external".as_slice()));
    }

    #[test]
    fn folded_function_emits_all_real_aliases_at_one_offset() {
        let mut output = ObjectFile::empty(false);
        let primary: RawString<'static> = b"ret_a".as_slice().into();
        let aliases = [primary, b"ret_b".as_slice().into()];
        output.add_function(primary, &aliases, &[0xc3]);

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let definitions = object
            .symbols()
            .filter(|symbol| symbol.is_definition() && symbol.address() == 0)
            .map(|symbol| symbol.name().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert!(definitions.iter().any(|name| name == "ret_a"));
        assert!(definitions.iter().any(|name| name == "ret_b"));
        assert!(definitions.iter().all(|name| name != "empty_stub"));
    }

    #[test]
    fn cross_object_call_uses_real_folded_identity() {
        let mut caller = ObjectFile::empty(false);
        let call_field = caller.append_section_data(caller.text_section_id, &[0; 4], 0x90);
        let callee: RawString<'static> = b"ret_a".as_slice().into();
        caller
            .add_relocation(callee, ObjectLocation::Extern, call_field, true)
            .unwrap();

        let bytes = caller.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let text = object.section_by_name(".text").unwrap();
        let (_, relocation) = text.relocations().next().unwrap();
        let object::RelocationTarget::Symbol(symbol_index) = relocation.target() else {
            panic!("cross-object call must target a symbol");
        };
        let symbol = object.symbol_by_index(symbol_index).unwrap();
        assert_eq!(symbol.name().unwrap(), "ret_a");
        assert!(symbol.is_undefined());
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
