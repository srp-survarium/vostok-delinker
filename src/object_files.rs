use crate::Env;
use crate::data_manifest::{DataDefinition, DataManifest, DataScope, DataStorage};
use crate::data_section_manifest::{
    ComdatSelection, DataSection, DataSectionManifest, SectionStorage,
};
use crate::pdb_symbols::PdbSymbols;
use crate::relocs::{RelocKind, RelocationEncoding};
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
    undefined_symbols: HashMap<Vec<u8>, SymbolId>,
    topology_sections: Vec<EmittedTopologySection>,
    definition_ranges: Vec<Vec<(usize, usize)>>,
    pending_data_comdats: Vec<PendingDataComdat>,
    comdat_leaders: HashMap<usize, SymbolId>,
}

#[derive(Clone, Copy)]
struct EmittedTopologySection {
    id: object::write::SectionId,
    storage: Option<SectionStorage>,
    rva: Option<usize>,
    size: usize,
}

#[derive(Clone, Copy)]
struct PendingDataComdat {
    ordinal: usize,
    section: object::write::SectionId,
    selection: ComdatSelection,
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

#[derive(Copy, Clone, Eq, PartialEq)]
enum SymbolReuse {
    CreateUnique,
    ReuseExisting,
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
        for object_file in this.objects.values_mut() {
            object_file.add_topology_section_relocations(
                matcher,
                coff_data,
                &relocs_rva,
                data_manifest,
            )?;
        }
        for definition in &definitions {
            let object_file = this.objects.get_mut(definition.object).unwrap();
            if !object_file.definition_uses_affine_topology(*definition) {
                object_file.add_data_relocations(
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
            undefined_symbols: HashMap::new(),
            topology_sections: Vec::new(),
            definition_ranges: Vec::new(),
            pending_data_comdats: Vec::new(),
            comdat_leaders: HashMap::new(),
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

        let mut topology_sections = Vec::with_capacity(sections.len());
        let mut pending_data_comdats = Vec::new();
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
            let id = object.add_section(Vec::new(), section.name.to_vec(), kind);
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
                            object.append_section_bss(id, section.size.to_u64(), section.alignment);
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
                    object.append_section_bss(id, section.size.to_u64(), section.alignment);
                }
                (Some(SectionStorage::Data | SectionStorage::Rdata), None) => {
                    object.set_section_data(id, vec![0; section.size], section.alignment);
                }
                (None, None) => object.set_section_data(id, Vec::new(), section.alignment),
                (None, Some(_)) => unreachable!("section manifest validates assigned RVAs"),
            }
            object.section_symbol(id);
            topology_sections.push(EmittedTopologySection {
                id,
                storage: section.storage,
                rva: section.rva,
                size: section.size,
            });

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
            if section.storage.is_some() && section.comdat_selection != ComdatSelection::None {
                pending_data_comdats.push(PendingDataComdat {
                    ordinal: section.ordinal,
                    section: id,
                    selection: section.comdat_selection,
                });
            }
        }

        let data_section_id = data_section_id
            .unwrap_or_else(|| object.add_section(Vec::new(), b".data".into(), SectionKind::Data));
        let rdata_section_id = rdata_section_id.unwrap_or_else(|| {
            object.add_section(Vec::new(), b".rdata".into(), SectionKind::ReadOnlyData)
        });
        let text_section_id = text_section_id
            .unwrap_or_else(|| object.add_section(Vec::new(), b".text".into(), SectionKind::Text));
        if pad_rdata {
            object.append_section_data(rdata_section_id, &0_u32.to_le_bytes(), 4);
        }

        Ok(Self {
            object,
            data_section_id,
            rdata_section_id,
            bss_section_id,
            text_section_id,
            undefined_symbols: HashMap::new(),
            topology_sections,
            definition_ranges: vec![Vec::new(); sections.len()],
            pending_data_comdats,
            comdat_leaders: HashMap::new(),
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
            self.add_relocation(
                reloc_name,
                ObjectLocation::Extern,
                reloc_offset,
                encoding,
                SymbolReuse::ReuseExisting,
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
                    SymbolReuse::ReuseExisting,
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
                    SymbolReuse::CreateUnique,
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
                    SymbolReuse::CreateUnique,
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
                    SymbolReuse::CreateUnique,
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
        let topology_section = definition
            .section_ordinal
            .map(|ordinal| {
                self.topology_sections
                    .get(ordinal - 1)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "reviewed data definition references absent section ordinal {ordinal}"
                        )
                    })
            })
            .transpose()?;
        let expected_storage = match definition.storage {
            DataStorage::Data => SectionStorage::Data,
            DataStorage::Rdata => SectionStorage::Rdata,
            DataStorage::Bss => SectionStorage::Bss,
        };
        let offset = if let Some(section) = topology_section {
            if section.storage != Some(expected_storage) {
                anyhow::bail!("data definition storage disagrees with its candidate section");
            }
            let section_offset = definition.section_offset.unwrap();
            let section_local_end = section_offset
                .checked_add(definition.size)
                .ok_or_else(|| anyhow::anyhow!("reviewed data section-local extent overflows"))?;
            if section_local_end > section.size {
                anyhow::bail!("reviewed data definition exceeds its assigned section");
            }
            if let Some(section_rva) = section.rva {
                let expected_rva = section_rva
                    .checked_add(section_offset)
                    .ok_or_else(|| anyhow::anyhow!("reviewed data section placement overflows"))?;
                if definition.rva != expected_rva {
                    anyhow::bail!(
                        "data definition RVA disagrees with its candidate section: expected {expected_rva:#x}, got {:#x}",
                        definition.rva
                    );
                }
            }

            let ranges = &mut self.definition_ranges[definition.section_ordinal.unwrap() - 1];
            let insertion = ranges
                .binary_search_by_key(&section_offset, |(start, _)| *start)
                .unwrap_or_else(|index| index);
            if (insertion > 0 && ranges[insertion - 1].1 > section_offset)
                || (insertion < ranges.len() && ranges[insertion].0 < section_local_end)
            {
                anyhow::bail!("reviewed data definitions overlap in their candidate section");
            }
            ranges.insert(insertion, (section_offset, section_local_end));

            if section.rva.is_none() && definition.storage != DataStorage::Bss {
                self.object.section_mut(section.id).data_mut()[section_offset..section_local_end]
                    .copy_from_slice(&coff_data[definition.rva..definition_end]);
            }
            ObjectOffset {
                offset: section_offset.to_u64(),
                section_id: section.id,
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
                            Vec::new(),
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
        let symbol = self.object.add_symbol(object::write::Symbol {
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
        if let Some(ordinal) = definition.section_ordinal
            && definition.section_offset == Some(0)
            && definition.scope == DataScope::External
        {
            self.comdat_leaders.entry(ordinal).or_insert(symbol);
        }
        Ok(())
    }

    fn finish_data_comdats(&mut self) -> anyhow::Result<()> {
        for pending in self.pending_data_comdats.clone() {
            let leader = self
                .comdat_leaders
                .get(&pending.ordinal)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "candidate data COMDAT section {} has no external offset-zero leader",
                        pending.ordinal
                    )
                })?;
            let kind = match pending.selection {
                ComdatSelection::NoDuplicates => ComdatKind::NoDuplicates,
                ComdatSelection::Any => ComdatKind::Any,
                ComdatSelection::SameSize => ComdatKind::SameSize,
                ComdatSelection::ExactMatch => ComdatKind::ExactMatch,
                ComdatSelection::Largest => ComdatKind::Largest,
                ComdatSelection::Newest => ComdatKind::Newest,
                ComdatSelection::Associative => anyhow::bail!(
                    "associative data COMDAT section {} requires a leader group",
                    pending.ordinal
                ),
                ComdatSelection::None => unreachable!(),
            };
            self.object.add_comdat(object::write::Comdat {
                kind,
                symbol: leader,
                sections: vec![pending.section],
            });
        }
        Ok(())
    }

    fn definition_uses_affine_topology(&self, definition: DataDefinition) -> bool {
        definition
            .section_ordinal
            .and_then(|ordinal| self.topology_sections.get(ordinal - 1))
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
            .iter()
            .copied()
            .filter(|section| section.rva.is_some())
            .collect::<Vec<_>>();
        for section in sections {
            let rva = section.rva.unwrap();
            let end = rva
                .checked_add(section.size)
                .ok_or_else(|| anyhow::anyhow!("candidate data section extent overflows"))?;
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
                        section_id: section.id,
                    },
                    matcher,
                    coff_data,
                    relocs_rva,
                    &mut visited,
                    data_manifest,
                    TargetMaterialization::ReferenceOnly,
                )?;
            }
        }
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

        let existing = match symbol_reuse {
            SymbolReuse::CreateUnique => None,
            SymbolReuse::ReuseExisting => self
                .object
                .symbol_id(name.as_bytes())
                .or_else(|| self.undefined_symbols.get(name.as_bytes()).copied()),
        };
        let symbol = if let Some(symbol) = existing {
            symbol
        } else {
            let symbol = self.object.add_symbol(object::write::Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size: u64::MAX,
                kind,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section,
                flags: object::SymbolFlags::None,
            });
            if symbol_reuse == SymbolReuse::ReuseExisting
                && section == object::write::SymbolSection::Undefined
            {
                self.undefined_symbols
                    .insert(name.as_bytes().to_vec(), symbol);
            }
            symbol
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
    use object::{Object as _, ObjectComdat as _, ObjectSection as _, ObjectSymbol as _};

    fn definition(scope: DataScope, section_offset: usize) -> DataDefinition {
        DataDefinition {
            symbol_name: RawString::from(&b"fixture"[..]),
            object: b"fixture.c",
            rva: 0,
            size: 4,
            storage: DataStorage::Data,
            alignment: 4,
            section_ordinal: None,
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

    #[test]
    fn repeated_external_relocations_reuse_one_undefined_symbol() {
        let mut object = ObjectFile::empty(false);
        let offset = object.append_section_data(object.text_section_id, &[0; 8], 0x90);
        let name = RawString::from(&b"external"[..]);

        object
            .add_relocation(
                name,
                ObjectLocation::Extern,
                offset,
                RelocationEncoding::Absolute,
                SymbolReuse::ReuseExisting,
            )
            .unwrap();
        object
            .add_relocation(
                name,
                ObjectLocation::Extern,
                offset + 4,
                RelocationEncoding::Absolute,
                SymbolReuse::ReuseExisting,
            )
            .unwrap();

        assert_eq!(object.undefined_symbols.len(), 1);
        assert!(
            object
                .undefined_symbols
                .contains_key(b"external".as_slice())
        );
    }

    #[test]
    fn folded_function_emits_all_pdb_aliases_at_one_offset() {
        let mut output = ObjectFile::empty(false);
        let primary = RawString::from(&b"real_a"[..]);
        let aliases = [primary, RawString::from(&b"real_b"[..])];
        output.add_function(primary, &aliases, &[0xc3]);

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let mut definitions = object
            .symbols()
            .filter(|symbol| {
                symbol.is_definition()
                    && symbol.kind() == object::SymbolKind::Text
                    && symbol.address() == 0
            })
            .map(|symbol| symbol.name().unwrap().to_owned())
            .collect::<Vec<_>>();
        definitions.sort_unstable();
        assert_eq!(definitions, ["real_a", "real_b"]);
    }

    #[test]
    fn emits_distinct_data_sections_and_comdat_group() {
        let sections = [
            DataSection {
                object: b"fixture.c",
                ordinal: 1,
                name: b".drectve",
                rva: None,
                size: 0,
                alignment: 1,
                characteristics: 0x0010_0a00,
                comdat_selection: ComdatSelection::None,
                associative_ordinal: None,
                storage: None,
            },
            DataSection {
                object: b"fixture.c",
                ordinal: 2,
                name: b".data",
                rva: Some(0x10),
                size: 4,
                alignment: 4,
                characteristics: 0xc030_0040,
                comdat_selection: ComdatSelection::None,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
            DataSection {
                object: b"fixture.c",
                ordinal: 3,
                name: b".data",
                rva: Some(0x20),
                size: 4,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: ComdatSelection::Any,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
        ];
        let mut image = vec![0_u8; 0x30];
        image[0x10..0x14].copy_from_slice(b"main");
        image[0x20..0x24].copy_from_slice(b"fold");
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
        for (name, rva, ordinal) in [(b"main".as_slice(), 0x10, 2), (b"fold".as_slice(), 0x20, 3)] {
            output
                .add_data_definition(
                    DataDefinition {
                        symbol_name: RawString::from(name),
                        object: b"fixture.c",
                        rva,
                        size: 4,
                        storage: DataStorage::Data,
                        alignment: 4,
                        section_ordinal: Some(ordinal),
                        section_offset: Some(0),
                        scope: DataScope::External,
                    },
                    &image,
                )
                .unwrap();
        }
        output.finish_data_comdats().unwrap();

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let parsed_sections = object.sections().collect::<Vec<_>>();
        assert_eq!(parsed_sections[0].name().unwrap(), ".drectve");
        assert_eq!(parsed_sections[1].data().unwrap(), b"main");
        assert_eq!(parsed_sections[2].data().unwrap(), b"fold");
        let comdats = object.comdats().collect::<Vec<_>>();
        assert_eq!(comdats.len(), 1);
        assert_eq!(comdats[0].kind(), ComdatKind::Any);
        assert_eq!(
            object
                .symbol_by_index(comdats[0].symbol())
                .unwrap()
                .name()
                .unwrap(),
            "fold"
        );
    }

    #[test]
    fn non_affine_topology_copies_reviewed_payloads_and_definition_relocations() {
        let sections = [DataSection {
            object: b"fixture.c",
            ordinal: 1,
            name: b".data",
            rva: None,
            size: 0x10,
            alignment: 8,
            characteristics: 0xc040_0040,
            comdat_selection: ComdatSelection::None,
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
                symbol_name: RawString::from(&b"left"[..]),
                object: b"fixture.c",
                rva: 0x10,
                size: 4,
                storage: DataStorage::Data,
                alignment: 4,
                section_ordinal: Some(1),
                section_offset: Some(0),
                scope: DataScope::External,
            },
            DataDefinition {
                symbol_name: RawString::from(&b"right"[..]),
                object: b"fixture.c",
                rva: 0x30,
                size: 8,
                storage: DataStorage::Data,
                alignment: 4,
                section_ordinal: Some(1),
                section_offset: Some(8),
                scope: DataScope::External,
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
                symbol: RawString::from(&b"external"[..]),
                target_rva: 0x40,
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
                .add_data_relocations(
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
            object: b"fixture.c",
            ordinal: 1,
            name: b".data",
            rva: None,
            size: 8,
            alignment: 4,
            characteristics: 0xc030_0040,
            comdat_selection: ComdatSelection::None,
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
            symbol_name: RawString::from(name),
            object: b"fixture.c",
            rva,
            size: 4,
            storage: DataStorage::Data,
            alignment: 1,
            section_ordinal: Some(1),
            section_offset: Some(offset),
            scope: DataScope::Local,
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
    fn topology_replays_relocations_for_each_folded_data_section() {
        let sections = [
            DataSection {
                object: b"fixture.c",
                ordinal: 1,
                name: b".data",
                rva: Some(0x10),
                size: 8,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: ComdatSelection::Any,
                associative_ordinal: None,
                storage: Some(SectionStorage::Data),
            },
            DataSection {
                object: b"fixture.c",
                ordinal: 2,
                name: b".data",
                rva: Some(0x10),
                size: 8,
                alignment: 4,
                characteristics: 0xc030_1040,
                comdat_selection: ComdatSelection::Any,
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
                        symbol_name: RawString::from(name),
                        object: b"fixture.c",
                        rva: 0x10,
                        size: 4,
                        storage: DataStorage::Data,
                        alignment: 4,
                        section_ordinal: Some(ordinal),
                        section_offset: Some(0),
                        scope: DataScope::External,
                    },
                    &image,
                )
                .unwrap();
        }

        let mut relocs = BTreeMap::new();
        relocs.insert(
            0x14,
            RelocKind::Static {
                symbol: RawString::from(&b"external"[..]),
                target_rva: 0x18,
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
            object: b"fixture.c",
            ordinal: 1,
            name: b".data",
            rva: Some(0x10),
            size: 4,
            alignment: 4,
            characteristics: 0xc030_0040,
            comdat_selection: ComdatSelection::None,
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
                    symbol_name: RawString::from(&b"too_large"[..]),
                    object: b"fixture.c",
                    rva: 0x10,
                    size: 5,
                    storage: DataStorage::Data,
                    alignment: 4,
                    section_ordinal: Some(1),
                    section_offset: Some(0),
                    scope: DataScope::External,
                },
                &image,
            )
            .unwrap_err();
        assert!(error.to_string().contains("exceeds its assigned section"));
    }
}
