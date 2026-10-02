use crate::Env;
use crate::common_symbol_manifest::CommonSymbolManifest;
use crate::data_manifest::{DataDefinition, DataManifest, DataScope, DataStorage};
use crate::data_section_manifest::{
    ComdatSelection, DataSection, DataSectionManifest, SectionChecksums, SectionStorage,
    SectionTopology,
};
use crate::pdb_symbols::{FunctionRelocationField, PdbSymbols};
use crate::reloc_alias_manifest::{RelocAliasManifest, RelocAliasObservations};
use crate::relocs::{
    CodeRelocationRecovery, ManifestCoverage, RelocKind, RelocationEncoding, WritableExtent,
    classify_exact_pdb_target,
};
use crate::symbol_matcher::{SymbolMatcher, canonical_name};
use crate::utils::{ToU64, ToUsize, contains, leak};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

use pdb2::{FallibleIterator, RawString};

use object::write::SymbolId;
use object::{ComdatKind, SectionFlags, SectionKind};

pub struct ObjectFiles<'a> {
    pub objects: HashMap<&'a [u8], ObjectFile>,
    section_checksums: SectionChecksums,
}

pub struct ObjectFile {
    pad_rdata: bool,
    pub object: object::write::Object<'static>,
    pub data_section_id: Option<object::write::SectionId>,
    pub rdata_section_id: Option<object::write::SectionId>,
    pub bss_section_id: Option<object::write::SectionId>,
    pub text_section_id: Option<object::write::SectionId>,
    undefined_symbols: HashMap<Vec<u8>, SymbolId>,
    common_symbols: HashSet<Vec<u8>>,
    conjured_copies: HashMap<ConjuredCopy, SymbolId>,
    topology_sections: Vec<EmittedTopologySection>,
    definition_ranges: Vec<Vec<(usize, usize)>>,
    reviewed_section_checksums: Vec<([u8; 8], u32)>,
}

#[derive(Clone, Copy)]
struct EmittedTopologySection {
    id: object::write::SectionId,
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
    Extern(object::SymbolKind),
}

/// The target a private copy stands for: a PDB string by its name, or the
/// constant/static word at an RVA spelled with a PDB name.
#[derive(Clone, Eq, Hash, PartialEq)]
struct ConjuredCopy {
    symbol: Vec<u8>,
    target_rva: Option<usize>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum TargetMaterialization {
    Materialize,
    ReferenceOnly,
}

#[derive(Default)]
struct FunctionClaims<'a> {
    sizes: HashMap<(&'a [u8], usize), usize>,
}

impl<'a> FunctionClaims<'a> {
    fn claim(&mut self, owner: &'a [u8], rva: usize, size: usize) -> anyhow::Result<bool> {
        match self.sizes.entry((owner, rva)) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(size);
                Ok(true)
            }
            std::collections::hash_map::Entry::Occupied(entry) if *entry.get() == size => Ok(false),
            std::collections::hash_map::Entry::Occupied(entry) => anyhow::bail!(
                "function records disagree on size for {} at RVA {rva:#x}: {} and {size}",
                String::from_utf8_lossy(owner),
                entry.get()
            ),
        }
    }
}

/// The candidate sections with a linked range, sorted by RVA.
struct PlacedSections<'a> {
    sections: Vec<(usize, usize, &'a DataSection)>,
}

impl<'a> PlacedSections<'a> {
    fn new(sections: &'a [DataSection]) -> Self {
        let mut sections = sections
            .iter()
            .filter_map(|section| Some((section.rva?, section.rva? + section.size, section)))
            .collect::<Vec<_>>();
        sections.sort_unstable_by_key(|(start, ..)| *start);
        Self { sections }
    }

    fn overlapping(&self, start: usize, end: usize) -> Option<&'a DataSection> {
        let candidates = self.sections.partition_point(|(rva, ..)| *rva < end);
        self.sections[..candidates]
            .iter()
            .rev()
            .find(|(_, section_end, _)| *section_end > start)
            .map(|(.., section)| *section)
    }
}

impl ObjectFiles<'_> {
    pub fn parse<'s, S>(
        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,

        symbols: &'s PdbSymbols,
        coff_data: &[u8],
        mut relocs_rva: BTreeMap<usize, RelocKind<'s>>,

        engine_paths: &[Vec<u8>],
        pad_empty_rdata: bool,
        matcher: &SymbolMatcher,
        data_manifest: &DataManifest,
        data_section_manifest: &DataSectionManifest,
        common_symbol_manifest: &CommonSymbolManifest,
        reloc_aliases: &RelocAliasManifest,
        observed_aliases: &mut RelocAliasObservations,
        manifest_coverage: ManifestCoverage,
        code_relocation_recovery: CodeRelocationRecovery,
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let topology = data_section_manifest.topology();
        let mut this = Self {
            objects: HashMap::new(),
            section_checksums: data_section_manifest.checksums(),
        };
        let empty_object = || ObjectFile::empty_with_topology(pad_empty_rdata, topology);

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

        for common in common_symbol_manifest.symbols() {
            this.objects
                .entry(common.object)
                .or_insert_with(empty_object)
                .add_common_symbol(common.name, common.size)?;
        }

        let definitions = data_manifest.definitions_in_emission_order();

        // A definition that no candidate section places is appended to its
        // object's storage section. One inside a placed section's linked range
        // would emit its bytes and relocations a second time.
        let placed = PlacedSections::new(data_section_manifest.sections());
        for definition in definitions {
            let definition_end = definition.rva.checked_add(definition.size).unwrap();
            if definition.section_ordinal.is_none()
                && let Some(section) = placed.overlapping(definition.rva, definition_end)
            {
                anyhow::bail!(
                    "data manifest definition `{}` in {} (RVA {:#x}..{:#x}) has no section \
                     ordinal but lies in section {} of {}",
                    definition.symbol_name,
                    String::from_utf8_lossy(definition.object),
                    definition.rva,
                    definition_end,
                    section.ordinal,
                    String::from_utf8_lossy(section.object),
                );
            }
            let section = match definition.storage {
                DataStorage::Rdata => env.rdata,
                DataStorage::Data | DataStorage::Bss => env.data,
            };
            if definition.rva < section.rva || definition_end > section.rva + section.size {
                anyhow::bail!(
                    "data manifest definition `{}` in {} (storage {:?}, RVA {:#x}..{:#x}) \
                     does not fit its PE section (RVA {:#x}..{:#x})",
                    String::from_utf8_lossy(definition.symbol_name.as_bytes()),
                    String::from_utf8_lossy(definition.object),
                    definition.storage,
                    definition.rva,
                    definition_end,
                    section.rva,
                    section.rva + section.size,
                );
            }
            let object_file = this
                .objects
                .entry(definition.object)
                .or_insert_with(empty_object);
            object_file.add_data_definition(*definition, coff_data)?;
        }
        for object_file in this.objects.values_mut() {
            object_file.add_topology_section_relocations(matcher, coff_data, &relocs_rva)?;
        }
        for definition in definitions {
            let object_file = this.objects.get_mut(definition.object).unwrap();
            if !object_file.definition_uses_affine_topology(*definition) {
                object_file.add_data_relocations(*definition, matcher, coff_data, &relocs_rva)?;
            }
        }

        let mut function_claims = FunctionClaims::default();
        let mut recovered_addends = HashMap::new();
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
                    engine_paths,
                )?
                else {
                    continue;
                };

                let fun_rva = env.text.rva + fun_offset.offset.to_usize();
                if symbols.is_incremental_trampoline(fun_rva) {
                    continue;
                }
                if !function_claims.claim(filename, fun_rva, fun_size)? {
                    continue;
                }
                let fun_bytes = resolve_code_relocations(
                    env.image_base,
                    fun_rva,
                    fun_size,
                    symbols,
                    coff_data,
                    &mut relocs_rva,
                    reloc_aliases,
                    observed_aliases,
                    data_manifest,
                    manifest_coverage,
                    WritableExtent::of(env),
                    code_relocation_recovery,
                    &mut recovered_addends,
                )?;

                let object_file = this.objects.entry(filename).or_insert_with(empty_object);

                let fun_name = match symbols.functions.get(&fun_rva) {
                    Some(overloads) => matcher.pick(overloads, canonical_name(overloads)),
                    _ => fun_name,
                };

                let fun_offset_in_coff_text = object_file.add_function(fun_name, &fun_bytes)?;

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
        let mut symbolless_objects = Vec::new();

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
            let mut bytes = object_file.object.write()?;
            let symbolless = symbolless_comdats(&bytes)?;
            if symbolless != 0 {
                symbolless_objects.push((path.clone(), symbolless));
            }
            match self.section_checksums {
                SectionChecksums::Reviewed => {
                    apply_reviewed_section_checksums(
                        &mut bytes,
                        &object_file.reviewed_section_checksums,
                    )?;
                }
                SectionChecksums::Zero => {
                    zero_section_checksums(&mut bytes)?;
                }
            }
            std::fs::write(&path, bytes)?;
        }
        if let Some((example, count)) = symbolless_objects.first() {
            eprintln!(
                "[comdat] {} object(s) carry COMDAT sections that define no symbol \
                 (e.g. {count} in {}); object readers ignore such a COMDAT and link.exe \
                 rejects it",
                symbolless_objects.len(),
                example.display()
            );
        }
        Ok(())
    }
}

impl ObjectFile {
    fn data_section(&mut self) -> object::write::SectionId {
        *self.data_section_id.get_or_insert_with(|| {
            self.object
                .add_section(Vec::new(), b".data".into(), SectionKind::Data)
        })
    }

    fn bss_section(&mut self) -> object::write::SectionId {
        *self.bss_section_id.get_or_insert_with(|| {
            self.object
                .add_section(Vec::new(), b".bss".into(), SectionKind::UninitializedData)
        })
    }

    fn rdata_section(&mut self) -> object::write::SectionId {
        if let Some(section_id) = self.rdata_section_id {
            return section_id;
        }
        let section_id =
            self.object
                .add_section(Vec::new(), b".rdata".into(), SectionKind::ReadOnlyData);
        pad_created_rdata(&mut self.object, section_id, self.pad_rdata);
        *self.rdata_section_id.insert(section_id)
    }

    fn text_section(&mut self) -> object::write::SectionId {
        *self.text_section_id.get_or_insert_with(|| {
            self.object
                .add_section(Vec::new(), b".text".into(), SectionKind::Text)
        })
    }

    fn empty_with_topology(pad_rdata: bool, topology: SectionTopology) -> Self {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Coff,
            object::Architecture::I386,
            object::Endianness::Little,
        );
        object.set_mangling(object::write::Mangling::None);

        let (data_section_id, rdata_section_id, text_section_id) = match topology {
            SectionTopology::Synthesized => (
                Some(object.add_section(Vec::new(), b".data".into(), SectionKind::Data)),
                Some(object.add_section(Vec::new(), b".rdata".into(), SectionKind::ReadOnlyData)),
                Some(object.add_section(Vec::new(), b".text".into(), SectionKind::Text)),
            ),
            SectionTopology::Exact => (None, None, None),
        };

        if let Some(rdata_section_id) = rdata_section_id {
            pad_created_rdata(&mut object, rdata_section_id, pad_rdata);
        }

        Self {
            pad_rdata,
            object,
            data_section_id,
            rdata_section_id,
            bss_section_id: None,
            text_section_id,
            undefined_symbols: HashMap::new(),
            common_symbols: HashSet::new(),
            conjured_copies: HashMap::new(),
            topology_sections: Vec::new(),
            definition_ranges: Vec::new(),
            reviewed_section_checksums: Vec::new(),
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
        let mut data_section_id = None;
        let mut rdata_section_id = None;
        let mut bss_section_id = None;
        let mut text_section_id = None;
        let mut reviewed_section_checksums = Vec::with_capacity(sections.len());

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
            let mut section_name = [0; 8];
            section_name[..section.name.len()].copy_from_slice(section.name);
            reviewed_section_checksums.push((section_name, section.checksum));
            topology_sections.push(EmittedTopologySection {
                id,
                storage: section.storage,
                rva: section.rva,
                size: section.size,
            });

            // Data the manifest does not place is appended to the first plain
            // section of its storage. A COMDAT holds only the symbol cl put in it
            // and a grouped section (`.CRT$XCU`) only its linker-sorted entries,
            // so neither may receive it; without a plain section one is created.
            let sink = section.comdat_selection == ComdatSelection::None;
            match section.storage {
                Some(SectionStorage::Data)
                    if sink && section.name == b".data" && data_section_id.is_none() =>
                {
                    data_section_id = Some(id)
                }
                Some(SectionStorage::Rdata)
                    if sink && section.name == b".rdata" && rdata_section_id.is_none() =>
                {
                    rdata_section_id = Some(id)
                }
                Some(SectionStorage::Bss)
                    if sink && section.name == b".bss" && bss_section_id.is_none() =>
                {
                    bss_section_id = Some(id)
                }
                None if section.name == b".text" && text_section_id.is_none() => {
                    text_section_id = Some(id)
                }
                _ => {}
            }
        }

        // The writer only needs the COMDAT's primary section, which its section
        // symbol identifies; associative sections join their leader's group.
        // Sections are contiguous by ordinal, as the manifest validates.
        for section in sections {
            let kind = match section.comdat_selection {
                ComdatSelection::None | ComdatSelection::Associative => continue,
                ComdatSelection::NoDuplicates => ComdatKind::NoDuplicates,
                ComdatSelection::Any => ComdatKind::Any,
                ComdatSelection::SameSize => ComdatKind::SameSize,
                ComdatSelection::ExactMatch => ComdatKind::ExactMatch,
                ComdatSelection::Largest => ComdatKind::Largest,
                ComdatSelection::Newest => ComdatKind::Newest,
            };
            let leader = topology_sections[section.ordinal - 1].id;
            let mut members = vec![leader];
            members.extend(
                sections
                    .iter()
                    .filter(|member| member.associative_ordinal == Some(section.ordinal))
                    .map(|member| topology_sections[member.ordinal - 1].id),
            );
            let symbol = object.section_symbol(leader);
            object.add_comdat(object::write::Comdat {
                kind,
                symbol,
                sections: members,
            });
        }

        // A reviewed `.rdata` keeps exactly its reviewed size; only a `.rdata`
        // created later for unplaced data is padded.
        Ok(Self {
            pad_rdata,
            object,
            data_section_id,
            rdata_section_id,
            bss_section_id,
            text_section_id,
            undefined_symbols: HashMap::new(),
            common_symbols: HashSet::new(),
            conjured_copies: HashMap::new(),
            topology_sections,
            definition_ranges: vec![Vec::new(); sections.len()],
            reviewed_section_checksums,
        })
    }
}

/// objdiff considers two allocations to match when their name OR their offset
/// into the relocation table is equal, so different data with different names
/// can match on offset alone. Four leading bytes in every `.rdata` the
/// delinker creates move those offsets apart.
fn pad_created_rdata(
    object: &mut object::write::Object,
    section_id: object::write::SectionId,
    pad_rdata: bool,
) {
    if pad_rdata {
        object.append_section_data(section_id, &0_u32.to_le_bytes(), 4);
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

    engine_paths: &[Vec<u8>],
) -> anyhow::Result<Option<&'static [u8]>> {
    let mut filename = None;

    let mut lines = program.lines_for_symbol(fun_offset);
    // Extracting only a single line should be enough to find a source file.
    if let Some(line_info) = lines.next()? {
        let file_info = program.get_file_info(line_info.file_index)?;
        filename = Some(string_table.get(file_info.name)?);
    }

    let location: &'static [u8] = match filename {
        // First prefix that matches wins. A build draws compilands from more than
        // one source tree - the engine's own `sources/`, and the Scaleform GFx
        // SDK that sits outside it - and with a single prefix the other tree's
        // compilands were dropped on BOTH sides, so those functions could never
        // pair. Give each tree the prefix that leaves the same relative path on
        // both sides and they key identically.
        Some(filename) => {
            let bytes = filename.as_bytes();
            match engine_paths
                .iter()
                .find_map(|prefix| bytes.strip_prefix(prefix.as_slice()))
            {
                Some(filename) => filename,
                None => return Ok(None),
            }
        }
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

/// A relative branch site is classified from scratch every time its function is
/// visited, so re-inserting one must yield the identical `Function` relocation —
/// the same overload slice. Anything else means two different callees were mapped
/// onto one site, i.e. a classification bug, so this asserts rather than returns.
fn assert_reinserted_branch_is_identical(
    previous: RelocKind,
    overloads: &[RawString<'static>],
    symbol: Option<RawString<'static>>,
) {
    let RelocKind::Function {
        overloads: previous_overloads,
        symbol: previous_symbol,
        ..
    } = previous
    else {
        unreachable!("a relative branch site can only hold a Function relocation");
    };
    assert_eq!(
        overloads.as_ptr(),
        previous_overloads.as_ptr(),
        "a relative branch site was reclassified to a different function",
    );
    assert_eq!(
        symbol, previous_symbol,
        "a relative branch site was reclassified to a different reviewed alias",
    );
}

/// Resolve relocations in the function.
///
/// And return the final resolved function assembly.
// @NOTE: There is no reason to grow `relocs_rva`, since these allocations
// are specific to the current function and don't need to be kept alive after
// the function is processed.
//
// At the same time `relocs_rva` sorts automatically!
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct DecodedAbsoluteOperandField {
    offset: usize,
}

fn decoded_absolute_operand_fields(
    decoder: &Decoder<'_>,
    instruction: &Instruction,
) -> [Option<DecodedAbsoluteOperandField>; 3] {
    let offsets = decoder.get_constant_offsets(instruction);
    let field = |offset: usize, size: usize| {
        (size == std::mem::size_of::<u32>()).then_some(DecodedAbsoluteOperandField { offset })
    };
    let immediate = match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => [None, None],
        _ => [
            field(offsets.immediate_offset(), offsets.immediate_size()),
            field(offsets.immediate_offset2(), offsets.immediate_size2()),
        ],
    };
    let displacement = (instruction.memory_base() == Register::None)
        .then(|| field(offsets.displacement_offset(), offsets.displacement_size()))
        .flatten();
    [displacement, immediate[0], immediate[1]]
}

/// Inline jump table entries of a function, by offset: retained absolute
/// relocation fields that hold a label of the function itself. The absolute
/// pass has already rewritten each to the label's offset from the function
/// start. An operand that addresses data inside the function lands here too,
/// so the decoder treats an entry as data only when it reaches it at an
/// instruction boundary.
fn inline_jump_table_entries(
    fun_rva: usize,
    fun_size: usize,
    symbols: &PdbSymbols,
    coff_data: &[u8],
    relocs_rva: &BTreeMap<usize, RelocKind>,
) -> BTreeMap<usize, usize> {
    let Some(own) = symbols.functions.get(&fun_rva) else {
        return BTreeMap::new();
    };
    let fun_end = fun_rva + fun_size;
    relocs_rva
        .range(fun_rva..fun_end)
        .filter_map(|(&site_rva, kind)| {
            let RelocKind::Function {
                overloads,
                encoding: RelocationEncoding::Absolute,
                ..
            } = kind
            else {
                return None;
            };
            if !std::ptr::eq(overloads.as_ptr(), own.as_ptr())
                || site_rva + std::mem::size_of::<u32>() > fun_end
            {
                return None;
            }
            let entry =
                bytemuck::pod_read_unaligned::<u32>(&coff_data[site_rva..site_rva + 4]).to_usize();
            (entry < fun_size).then_some((site_rva - fun_rva, entry))
        })
        .collect()
}

/// Offsets where a function's code is known to start: the entries of every
/// jump table a sweep that skips the tables reaches, and every internal branch
/// target it decodes. The sweep repeats until no label is added, since a label
/// found late can mark code that an earlier sweep skipped as part of a table.
///
/// Only a table reached at an instruction boundary gives labels: an entry that
/// is the operand of an instruction holds a data address, such as the byte
/// index table after a jump table, and resuming there would decode data.
fn code_labels(
    code: &[u8],
    fun_va: u64,
    table_entries: &BTreeMap<usize, usize>,
) -> anyhow::Result<BTreeSet<usize>> {
    let mut labels = BTreeSet::new();
    loop {
        let known = labels.len();
        let mut decoder = Decoder::with_ip(32, code, fun_va, DecoderOptions::NONE);
        let mut ix = Instruction::default();
        while decoder.can_decode() {
            let position = decoder.position();
            if table_entries.contains_key(&position) {
                let mut end = position;
                while let Some(entry) = table_entries.get(&end) {
                    labels.insert(*entry);
                    end += std::mem::size_of::<u32>();
                }
                let resume = code_after_table(position, table_entries, &labels);
                if resume >= code.len() {
                    break;
                }
                decoder.set_position(resume)?;
                decoder.set_ip(fun_va + resume as u64);
                continue;
            }
            decoder.decode_out(&mut ix);
            if !matches!(
                ix.flow_control(),
                FlowControl::ConditionalBranch
                    | FlowControl::UnconditionalBranch
                    | FlowControl::Call
            ) {
                continue;
            }
            let target = match ix.op0_kind() {
                OpKind::NearBranch16 => u64::from(ix.near_branch16()),
                OpKind::NearBranch32 => u64::from(ix.near_branch32()),
                _ => continue,
            };
            if let Some(offset) = target.checked_sub(fun_va)
                && (offset as usize) < code.len()
            {
                labels.insert(offset as usize);
            }
        }
        if labels.len() == known {
            return Ok(labels);
        }
    }
}

/// Where code resumes after the jump table at `position`: past its entries,
/// and past any byte index table that follows, at the next label.
fn code_after_table(
    position: usize,
    table_entries: &BTreeMap<usize, usize>,
    labels: &BTreeSet<usize>,
) -> usize {
    let mut end = position;
    while table_entries.contains_key(&end) {
        end += std::mem::size_of::<u32>();
    }
    labels.range(end..).next().copied().unwrap_or(end)
}

fn resolve_code_relocations<'s>(
    image_base: u32,

    fun_rva: usize,
    fun_size: usize,

    symbols: &'s PdbSymbols,

    coff_data: &[u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    reloc_aliases: &RelocAliasManifest,
    observed_aliases: &mut RelocAliasObservations,
    data_manifest: &DataManifest,
    manifest_coverage: ManifestCoverage,
    writable: WritableExtent,
    code_relocation_recovery: CodeRelocationRecovery,
    // Addends of the operand fields recovered so far, by site. A body that
    // several objects own is decoded once per owner and must read the same.
    recovered_addends: &mut HashMap<usize, u32>,
) -> anyhow::Result<Vec<u8>> {
    let fun_va = image_base.to_usize() + fun_rva;

    // @NOTE: Requires a new allocation, since capstone cannot borrow function code mutably.
    let mut fun_bytes = coff_data[fun_rva..fun_rva + fun_size].to_vec();

    let code = &coff_data[fun_rva..fun_rva + fun_size];
    let mut decoder = Decoder::with_ip(32, code, fun_va as u64, DecoderOptions::NONE);
    let mut ix = Instruction::default();

    let table_entries =
        inline_jump_table_entries(fun_rva, fun_size, symbols, coff_data, relocs_rva);
    let labels = code_labels(code, fun_va as u64, &table_entries)?;

    while decoder.can_decode() {
        let position = decoder.position();
        if table_entries.contains_key(&position) {
            // A linear sweep must not decode a jump table as code: its last
            // bytes can swallow the opcode of the next instruction and hide
            // that instruction's relocation.
            let resume = code_after_table(position, &table_entries, &labels);
            if resume >= fun_size {
                break;
            }
            decoder.set_position(resume)?;
            decoder.set_ip((fun_va + resume) as u64);
            continue;
        }
        decoder.decode_out(&mut ix);

        match code_relocation_recovery {
            CodeRelocationRecovery::RetainedOnly => {}
            CodeRelocationRecovery::ExactPdbInstructionOperands => {
                let instruction_offset = (ix.ip() - fun_va as u64) as usize;
                for field in decoded_absolute_operand_fields(&decoder, &ix)
                    .into_iter()
                    .flatten()
                {
                    let field_offset = instruction_offset + field.offset;
                    let reloc_rva = fun_rva + field_offset;
                    if relocs_rva.contains_key(&reloc_rva) {
                        if let Some(addend) = recovered_addends.get(&reloc_rva) {
                            fun_bytes[field_offset..field_offset + 4]
                                .copy_from_slice(&addend.to_le_bytes());
                        }
                        continue;
                    }
                    let FunctionRelocationField::Within { .. } =
                        symbols.relocation_field_in_function(fun_rva, reloc_rva)
                    else {
                        continue;
                    };
                    let encoded_va =
                        bytemuck::pod_read_unaligned::<u32>(&coff_data[reloc_rva..reloc_rva + 4]);
                    let Some(target_rva) =
                        encoded_va.checked_sub(image_base).map(ToUsize::to_usize)
                    else {
                        continue;
                    };
                    let Some((kind, addend)) = classify_exact_pdb_target(
                        symbols,
                        data_manifest,
                        reloc_aliases,
                        observed_aliases,
                        manifest_coverage,
                        writable,
                        fun_rva,
                        reloc_rva,
                        target_rva,
                    )?
                    else {
                        continue;
                    };
                    fun_bytes[field_offset..field_offset + 4]
                        .copy_from_slice(&addend.to_le_bytes());
                    relocs_rva.insert(reloc_rva, kind);
                    recovered_addends.insert(reloc_rva, addend);
                }
            }
        }

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

        let linked_target_rva = target_va - u64::from(image_base);
        let target_rva = symbols
            .resolve_incremental_trampoline(linked_target_rva.to_usize())
            .to_u64();

        // A call to the function's own entry is a recursive call, which the
        // compiler relocates against the function symbol.
        let recursive_call =
            ix.flow_control() == FlowControl::Call && target_rva.to_usize() == fun_rva;
        let internal_branch = linked_target_rva == target_rva
            && !recursive_call
            && (fun_rva..fun_rva + fun_size).contains(&(target_rva.to_usize()));
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
        let symbol = match symbols.relocation_field_in_function(fun_rva, reloc_rva) {
            FunctionRelocationField::Within { .. } => reloc_aliases.resolve_function_alias(
                fun_rva,
                target_rva.to_usize(),
                reloc_rva,
                overloads,
                observed_aliases,
            )?,
            FunctionRelocationField::MissingFunction
            | FunctionRelocationField::UnknownExtent
            | FunctionRelocationField::OutsideExtent
            | FunctionRelocationField::FieldOverflow => None,
        };

        fun_bytes[offset_in_fun - 4..offset_in_fun].copy_from_slice(&0_u32.to_le_bytes());
        let old_reloc = relocs_rva.insert(
            reloc_rva,
            RelocKind::Function {
                overloads,
                symbol,
                encoding: RelocationEncoding::Relative,
            },
        );

        if let Some(old_reloc) = old_reloc {
            assert_reinserted_branch_is_identical(old_reloc, overloads, symbol);
        }
    }

    Ok(fun_bytes)
}

impl ObjectFile {
    fn add_common_symbol(&mut self, name: &[u8], size: u64) -> anyhow::Result<()> {
        if self.object.symbol_id(name).is_some() {
            anyhow::bail!(
                "COMMON symbol {} is already a symbol of its object",
                String::from_utf8_lossy(name)
            );
        }
        self.object.add_symbol(object::write::Symbol {
            name: name.to_vec(),
            value: 0,
            size,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Common,
            flags: object::SymbolFlags::None,
        });
        self.common_symbols.insert(name.to_vec());
        Ok(())
    }

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
        target_materialization: TargetMaterialization,
    ) -> anyhow::Result<()> {
        let reloc_name = reloc_kind.get_name(matcher);
        let reloc_name = reloc_name.as_raw_string();

        // A conjured word named like a COMMON symbol of this object owns no bytes
        // to copy; the reference binds to the COMMON symbol.
        if let RelocKind::ConjuredStatic { .. } | RelocKind::ConjuredConstant { .. } = reloc_kind
            && self.common_symbols.contains(reloc_name.as_bytes())
        {
            self.add_relocation(
                reloc_name,
                ObjectLocation::Extern(object::SymbolKind::Data),
                reloc_offset,
                RelocationEncoding::Absolute,
            )?;
            return Ok(());
        }

        // An object holds one private copy per conjured target; every further
        // reference binds to it, as the compiler's single definition would.
        let copy = match (target_materialization, reloc_kind) {
            (TargetMaterialization::Materialize, RelocKind::ConjuredString { symbol, .. }) => {
                Some(ConjuredCopy {
                    symbol: symbol.as_bytes().to_vec(),
                    target_rva: None,
                })
            }
            (
                TargetMaterialization::Materialize,
                RelocKind::ConjuredConstant { symbol, target_rva }
                | RelocKind::ConjuredStatic {
                    symbol,
                    target_rva,
                    storage: DataStorage::Data | DataStorage::Rdata,
                },
            ) => Some(ConjuredCopy {
                symbol: symbol.as_bytes().to_vec(),
                target_rva: Some(target_rva),
            }),
            _ => None,
        };
        if let Some(copy) = &copy
            && let Some(&symbol) = self.conjured_copies.get(copy)
        {
            self.add_symbol_relocation(symbol, reloc_offset, RelocationEncoding::Absolute)?;
            return Ok(());
        }

        // `Function` and `ReviewedData` reference a real definition elsewhere; a
        // `Conjured*` target is materialized as a private per-TU copy, unless the
        // caller only wants a reference.
        match reloc_kind {
            RelocKind::Import { .. } => {
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern(reloc_kind.external_symbol_kind()),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
            }

            RelocKind::Function {
                overloads: _,
                encoding,
                ..
            } => {
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern(reloc_kind.external_symbol_kind()),
                    reloc_offset,
                    encoding,
                )?;
            }

            RelocKind::ReviewedData { .. } => {
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern(reloc_kind.external_symbol_kind()),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
            }

            RelocKind::ConjuredString { .. }
            | RelocKind::ConjuredConstant { .. }
            | RelocKind::ConjuredStatic { .. }
                if target_materialization == TargetMaterialization::ReferenceOnly =>
            {
                // All `.rdata`/`.data` conjured data referenced from inside a
                // reviewed definition is considered external: emit an undefined
                // reference, never a local copy. Nothing here owns it, so it
                // resolves by name and dangles until the target is itself reviewed.
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern(reloc_kind.external_symbol_kind()),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
            }

            RelocKind::ConjuredString { symbol: _, data } => {
                let rdata_section_id = self.rdata_section();
                let const_offset_in_coff_rdata =
                    self.append_section_data(rdata_section_id, data, 0x00);

                let symbol = self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
                self.conjured_copies.insert(copy.unwrap(), symbol);
            }

            RelocKind::ConjuredConstant {
                symbol: _,
                target_rva,
            } => {
                let new_data =
                    bytemuck::pod_read_unaligned::<[u8; 4]>(&coff_data[target_rva..target_rva + 4]);
                let rdata_section_id = self.rdata_section();
                let const_offset_in_coff_rdata =
                    self.append_section_data(rdata_section_id, &new_data, 0x00);
                let symbol = self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
                self.conjured_copies.insert(copy.unwrap(), symbol);

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
                            TargetMaterialization::Materialize,
                        )?;
                    }
                }
            }

            RelocKind::ConjuredStatic {
                storage: DataStorage::Bss,
                ..
            } => {
                // Zero-fill storage has no bytes or relocations to copy, and a
                // copy would only grow this object's own `.bss`.
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Extern(reloc_kind.external_symbol_kind()),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
            }

            RelocKind::ConjuredStatic {
                symbol: _,
                target_rva,
                storage: _,
            } => {
                let new_data =
                    bytemuck::pod_read_unaligned::<[u8; 4]>(&coff_data[target_rva..target_rva + 4]);
                let data_section_id = self.data_section();
                let static_offset_in_coff_data =
                    self.append_section_data(data_section_id, &new_data, 0x00);
                let symbol = self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(static_offset_in_coff_data),
                    reloc_offset,
                    RelocationEncoding::Absolute,
                )?;
                self.conjured_copies.insert(copy.unwrap(), symbol);

                // Same cycle guard as the ConjuredConstant arm above.
                if let Some(reloc_kind) = relocs_rva.get(&target_rva) {
                    if visited.insert(target_rva) {
                        self.add_relocation_at(
                            *reloc_kind,
                            static_offset_in_coff_data,
                            matcher,
                            coff_data,
                            relocs_rva,
                            visited,
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
                DataStorage::Data => {
                    let section_id = self.data_section();
                    ObjectOffset {
                        offset: self.object.append_section_data(
                            section_id,
                            &coff_data[definition.rva..definition_end],
                            definition.alignment,
                        ),
                        section_id,
                    }
                }
                DataStorage::Rdata => {
                    let section_id = self.rdata_section();
                    ObjectOffset {
                        offset: self.object.append_section_data(
                            section_id,
                            &coff_data[definition.rva..definition_end],
                            definition.alignment,
                        ),
                        section_id,
                    }
                }
                DataStorage::Bss => {
                    let section_id = self.bss_section();
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
                "duplicate data symbol {} in owner object",
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
    ) -> anyhow::Result<()> {
        let definition_end = definition.rva.checked_add(definition.size).unwrap();
        let symbol_id = self
            .object
            .symbol_id(definition.symbol_name.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("missing emitted data symbol"))?;
        let symbol = self.object.symbol(symbol_id);
        let object::write::SymbolSection::Section(section_id) = symbol.section else {
            anyhow::bail!("emitted data symbol has no output section");
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
    ) -> anyhow::Result<SymbolId> {
        // The location decides symbol identity. `Extern` is a reference: one symbol
        // per external name, reused if this object already emitted it and resolving
        // to a local definition when this object defines it. `Offset` is a fresh
        // local allocation, always its own symbol.
        let symbol = match location {
            // Reuse the defined symbol when this object owns it, otherwise keep one
            // undefined symbol per name. The writer indexes only defined symbols, so
            // undefined identities live in `undefined_symbols`.
            ObjectLocation::Extern(kind) => match self.object.symbol_id(name.as_bytes()) {
                Some(symbol) => symbol,
                None => {
                    let writer = &mut self.object;
                    *self
                        .undefined_symbols
                        .entry(name.as_bytes().to_vec())
                        .or_insert_with(|| {
                            writer.add_symbol(object::write::Symbol {
                                name: name.as_bytes().to_vec(),
                                value: 0,
                                size: u64::MAX,
                                kind,
                                scope: object::SymbolScope::Linkage,
                                weak: false,
                                section: object::write::SymbolSection::Undefined,
                                flags: object::SymbolFlags::None,
                            })
                        })
                }
            },
            ObjectLocation::Offset(ObjectOffset { offset, section_id }) => {
                let kind = if Some(section_id) == self.text_section_id {
                    object::SymbolKind::Text
                } else {
                    object::SymbolKind::Data
                };
                self.object.add_symbol(object::write::Symbol {
                    name: name.as_bytes().to_vec(),
                    value: offset,
                    size: u64::MAX,
                    kind,
                    scope: object::SymbolScope::Linkage,
                    weak: false,
                    section: object::write::SymbolSection::Section(section_id),
                    flags: object::SymbolFlags::None,
                })
            }
        };

        self.add_symbol_relocation(symbol, offset, encoding)?;
        Ok(symbol)
    }

    fn add_symbol_relocation(
        &mut self,
        symbol: SymbolId,
        offset: ObjectOffset,
        encoding: RelocationEncoding,
    ) -> anyhow::Result<()> {
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

    fn add_function(&mut self, name: RawString, body: &[u8]) -> anyhow::Result<ObjectOffset> {
        let existing = self.object.symbol_id(name.as_bytes());
        let undefined = self.undefined_symbols.get(name.as_bytes()).copied();
        let existing_symbol = match (existing, undefined) {
            (None, None) => None,
            // A PDB can give two distinct bodies one name inside one object (a
            // local class method in two copies of its enclosing function). Each
            // body keeps its own definition, as before forward references were
            // upgraded in place.
            (Some(defined), None) if self.is_function_definition(defined) => None,
            (indexed_id, Some(undefined_id))
                if indexed_id.is_none() || indexed_id == Some(undefined_id) =>
            {
                let symbol = self.object.symbol(undefined_id);
                anyhow::ensure!(
                    symbol.value == 0
                        && symbol.size == u64::MAX
                        && symbol.kind == object::SymbolKind::Text
                        && symbol.scope == object::SymbolScope::Linkage
                        && !symbol.weak
                        && symbol.section == object::write::SymbolSection::Undefined
                        && matches!(symbol.flags, object::SymbolFlags::None),
                    "incompatible undefined function symbol {}",
                    String::from_utf8_lossy(name.as_bytes())
                );
                Some(undefined_id)
            }
            _ => anyhow::bail!(
                "incompatible pre-existing function symbol {}",
                String::from_utf8_lossy(name.as_bytes())
            ),
        };

        let text_section_id = self.text_section();
        let fun_offset_in_coff_text = self.append_section_data(text_section_id, body, 0x90);
        let definition = object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: fun_offset_in_coff_text.offset,
            size: u64::MAX,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(fun_offset_in_coff_text.section_id),
            flags: object::SymbolFlags::None,
        };
        if let Some(symbol_id) = existing_symbol {
            *self.object.symbol_mut(symbol_id) = definition;
            let removed = self.undefined_symbols.remove(name.as_bytes());
            debug_assert_eq!(removed, Some(symbol_id));
        } else {
            self.object.add_symbol(definition);
        }

        Ok(fun_offset_in_coff_text)
    }

    fn is_function_definition(&self, symbol_id: SymbolId) -> bool {
        let symbol = self.object.symbol(symbol_id);
        symbol.kind == object::SymbolKind::Text
            && matches!(symbol.section, object::write::SymbolSection::Section(_))
    }
}

// Parse PDB symbols by iterating through symbol table and then through all modules

enum Name<'a> {
    Borrowed(RawString<'a>),
    Owned(Vec<u8>),
}

impl<'a> RelocKind<'a> {
    fn external_symbol_kind(self) -> object::SymbolKind {
        match self {
            Self::Function { .. } => object::SymbolKind::Text,
            Self::Import { .. }
            | Self::ReviewedData { .. }
            | Self::ConjuredString { .. }
            | Self::ConjuredConstant { .. }
            | Self::ConjuredStatic { .. } => object::SymbolKind::Unknown,
        }
    }

    fn get_name(self, matcher: &SymbolMatcher) -> Name<'a> {
        match self {
            Self::Import { symbol } => Name::Borrowed(symbol),
            Self::Function {
                overloads, symbol, ..
            } => Name::Borrowed(
                symbol.unwrap_or_else(|| matcher.pick(overloads, canonical_name(overloads))),
            ),
            Self::ConjuredString { symbol, data } => {
                let reloc_name = get_constant_name(symbol, data);
                Name::Owned(reloc_name)
            }
            Self::ReviewedData { symbol } => Name::Borrowed(symbol),
            Self::ConjuredConstant {
                symbol,
                target_rva: _,
            } => Name::Borrowed(symbol),
            Self::ConjuredStatic { symbol, .. } => Name::Borrowed(symbol),
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

/// The number of non-associative COMDAT sections without a symbol after their
/// section symbol. That symbol is the COMDAT symbol: link.exe requires it and
/// object readers find the group through it. A manifest can declare a COMDAT
/// that nothing is placed into, such as a second `.text` COMDAT while every
/// function lands in the first `.text` section.
fn symbolless_comdats(bytes: &[u8]) -> anyhow::Result<usize> {
    use object::read::coff::ImageSymbol as _;
    use object::{Object as _, ObjectComdat as _, ObjectSection as _};

    let file = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)?;
    let grouped = file
        .comdats()
        .filter_map(|comdat| comdat.sections().next())
        .collect::<HashSet<_>>();
    let mut symbolless = 0;
    for section in file.sections() {
        let object::SectionFlags::Coff { characteristics } = section.flags() else {
            continue;
        };
        let selection = file
            .coff_symbol_table()
            .iter()
            .find(|(_, symbol)| {
                symbol.has_aux_section()
                    && symbol.section_number.get(object::LittleEndian) as usize == section.index().0
            })
            .and_then(|(index, _)| file.coff_symbol_table().aux_section(index).ok())
            .map_or(0, |aux| aux.selection);
        if characteristics & object::pe::IMAGE_SCN_LNK_COMDAT != 0
            && selection != object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE
            && !grouped.contains(&section.index())
        {
            symbolless += 1;
        }
    }
    Ok(symbolless)
}

/// The checksum field of one section-definition auxiliary record.
struct SectionChecksumField {
    section_number: usize,
    section_name: [u8; 8],
    offset: usize,
}

fn section_checksum_fields(bytes: &[u8]) -> anyhow::Result<Vec<SectionChecksumField>> {
    use object::endian::LittleEndian;
    use object::read::SectionIndex;

    let coff = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)?;
    let symbol_table_offset = coff.coff_header().pointer_to_symbol_table.get(LittleEndian) as usize;
    let sections = coff.coff_section_table();
    let symbols = coff.coff_symbol_table();
    let checksum_in_aux = std::mem::offset_of!(object::pe::ImageAuxSymbolSection, check_sum);
    let mut fields = Vec::new();

    for (index, symbol) in symbols.iter() {
        let section_number = symbol.section_number.get(LittleEndian) as usize;
        if symbol.storage_class != object::pe::IMAGE_SYM_CLASS_STATIC
            || symbol.number_of_aux_symbols != 1
            || symbol.value.get(LittleEndian) != 0
            || symbol.typ.get(LittleEndian) != object::pe::IMAGE_SYM_TYPE_NULL
            || section_number == 0
            || section_number > sections.len()
        {
            continue;
        }
        let section = sections.section(SectionIndex(section_number))?;
        if symbol.name != section.name {
            continue;
        }
        symbols.aux_section(index)?;
        let offset = symbol_table_offset
            .checked_add(
                (index.0 + 1)
                    .checked_mul(object::pe::IMAGE_SIZEOF_SYMBOL)
                    .ok_or_else(|| anyhow::anyhow!("COFF auxiliary symbol offset overflows"))?,
            )
            .and_then(|offset| offset.checked_add(checksum_in_aux))
            .ok_or_else(|| anyhow::anyhow!("COFF section checksum offset overflows"))?;
        bytes
            .get(offset..offset + std::mem::size_of::<u32>())
            .ok_or_else(|| anyhow::anyhow!("COFF section checksum is outside the symbol table"))?;
        fields.push(SectionChecksumField {
            section_number,
            section_name: section.name,
            offset,
        });
    }
    Ok(fields)
}

fn apply_reviewed_section_checksums(
    bytes: &mut [u8],
    reviewed: &[([u8; 8], u32)],
) -> anyhow::Result<usize> {
    let mut seen = vec![false; reviewed.len()];
    let mut writes = Vec::with_capacity(reviewed.len());
    for field in section_checksum_fields(bytes)? {
        if field.section_number > reviewed.len() {
            continue;
        }
        let (expected_name, checksum) = reviewed[field.section_number - 1];
        if field.section_name != expected_name {
            anyhow::bail!("reviewed section checksum order/name mismatch");
        }
        if std::mem::replace(&mut seen[field.section_number - 1], true) {
            anyhow::bail!("duplicate COFF section-definition symbol");
        }
        writes.push((field.offset, checksum));
    }
    if seen.iter().any(|seen| !seen) {
        anyhow::bail!("reviewed COFF section has no section-definition symbol");
    }
    for (offset, checksum) in writes {
        bytes[offset..offset + std::mem::size_of::<u32>()].copy_from_slice(&checksum.to_le_bytes());
    }
    Ok(seen.len())
}

fn zero_section_checksums(bytes: &mut [u8]) -> anyhow::Result<usize> {
    let fields = section_checksum_fields(bytes)?;
    for field in &fields {
        bytes[field.offset..field.offset + std::mem::size_of::<u32>()].fill(0);
    }
    Ok(fields.len())
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
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    fn decoded_absolute_fields(code: &[u8]) -> Vec<(usize, u32)> {
        let mut decoder = Decoder::new(32, code, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut fields = Vec::new();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let instruction_offset = instruction.ip() as usize;
            for field in decoded_absolute_operand_fields(&decoder, &instruction)
                .into_iter()
                .flatten()
            {
                let offset = instruction_offset + field.offset;
                let value = bytemuck::pod_read_unaligned::<u32>(&code[offset..offset + 4]);
                fields.push((offset, value));
            }
        }

        fields
    }

    #[test]
    fn absolute_recovery_uses_only_decoded_operand_fields() {
        assert_eq!(
            decoded_absolute_fields(&[0xb8, 0x00, 0x20, 0x40, 0x00]),
            vec![(1, 0x0040_2000)]
        );
        assert_eq!(
            decoded_absolute_fields(&[0xa1, 0x00, 0x30, 0x40, 0x00]),
            vec![(1, 0x0040_3000)]
        );
    }

    #[test]
    fn absolute_recovery_excludes_branches_and_raw_address_words() {
        assert!(decoded_absolute_fields(&[0xe8, 0x00, 0x20, 0x40, 0x00]).is_empty());
        assert!(decoded_absolute_fields(&[0x90, 0x00, 0x20, 0x40, 0x00]).is_empty());
        assert!(decoded_absolute_fields(&[0x8b, 0x80, 0x00, 0x20, 0x40, 0x00]).is_empty());
    }

    #[test]
    fn stripped_mode_recovers_an_exact_operand_while_absent_mode_does_not() {
        let image_base = 0x0040_0000;
        let function_rva = 0x1000;
        let target_rva = 0x2000;
        let linked_function = [0xb8, 0x00, 0x20, 0x40, 0x00, 0xc3];
        let mut coff_data = vec![0; function_rva + linked_function.len()];
        coff_data[function_rva..].copy_from_slice(&linked_function);

        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"owner"[..]),
                Some(linked_function.len()),
            )
            .unwrap();
        symbols
            .add_function_at_rva(target_rva, RawString::from(&b"target"[..]), Some(1))
            .unwrap();
        let aliases = RelocAliasManifest::default();
        let data_manifest = DataManifest::default();

        let mut retained_relocations = BTreeMap::new();
        let retained = resolve_code_relocations(
            image_base,
            function_rva,
            linked_function.len(),
            &symbols,
            &coff_data,
            &mut retained_relocations,
            &aliases,
            &mut RelocAliasObservations::default(),
            &data_manifest,
            ManifestCoverage::AllowPartial { fences: &[] },
            WritableExtent::all_initialized(),
            crate::relocs::BaseRelocationSource::Absent.code_relocation_recovery(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert_eq!(retained, linked_function);
        assert!(retained_relocations.is_empty());

        let mut recovered_relocations = BTreeMap::new();
        let recovered = resolve_code_relocations(
            image_base,
            function_rva,
            linked_function.len(),
            &symbols,
            &coff_data,
            &mut recovered_relocations,
            &aliases,
            &mut RelocAliasObservations::default(),
            &data_manifest,
            ManifestCoverage::AllowPartial { fences: &[] },
            WritableExtent::all_initialized(),
            crate::relocs::BaseRelocationSource::Stripped.code_relocation_recovery(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert_eq!(recovered, [0xb8, 0, 0, 0, 0, 0xc3]);
        assert!(matches!(
            recovered_relocations.get(&(function_rva + 1)),
            Some(RelocKind::Function {
                overloads,
                encoding: RelocationEncoding::Absolute,
                ..
            }) if *overloads == [RawString::from(&b"target"[..])]
        ));

        // A body that two objects own is decoded twice; both copies carry the
        // recovered addend, not the linked address.
        let mut relocations = BTreeMap::new();
        let mut recovered_addends = HashMap::new();
        for _ in 0..2 {
            let copy = resolve_code_relocations(
                image_base,
                function_rva,
                linked_function.len(),
                &symbols,
                &coff_data,
                &mut relocations,
                &aliases,
                &mut RelocAliasObservations::default(),
                &data_manifest,
                ManifestCoverage::AllowPartial { fences: &[] },
                WritableExtent::all_initialized(),
                crate::relocs::BaseRelocationSource::Stripped.code_relocation_recovery(),
                &mut recovered_addends,
            )
            .unwrap();
            assert_eq!(copy, [0xb8, 0, 0, 0, 0, 0xc3]);
        }
    }

    #[test]
    fn relative_call_through_incremental_trampoline_targets_the_body() {
        let image_base = 0x0040_0000;
        let function_rva = 0x1000;
        let trampoline_rva = 0x2000;
        let target_rva = 0x3000;
        let linked_function = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3];
        let mut coff_data = vec![0; function_rva + linked_function.len()];
        coff_data[function_rva..].copy_from_slice(&linked_function);

        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"owner"[..]),
                Some(linked_function.len()),
            )
            .unwrap();
        symbols
            .add_function_at_rva(target_rva, RawString::from(&b"body"[..]), Some(1))
            .unwrap();
        symbols
            .add_incremental_trampoline_at_rva(trampoline_rva, target_rva, 5)
            .unwrap();

        let mut relocations = BTreeMap::new();
        let resolved = resolve_code_relocations(
            image_base,
            function_rva,
            linked_function.len(),
            &symbols,
            &coff_data,
            &mut relocations,
            &RelocAliasManifest::default(),
            &mut RelocAliasObservations::default(),
            &DataManifest::default(),
            ManifestCoverage::AllowPartial { fences: &[] },
            WritableExtent::all_initialized(),
            CodeRelocationRecovery::RetainedOnly,
            &mut HashMap::new(),
        )
        .unwrap();

        assert_eq!(resolved, [0xe8, 0, 0, 0, 0, 0xc3]);
        let RelocKind::Function {
            overloads,
            encoding: RelocationEncoding::Relative,
            ..
        } = relocations[&(function_rva + 1)]
        else {
            panic!("expected a relative function relocation");
        };
        assert_eq!(overloads[0].as_bytes(), b"body");
    }

    fn resolve_fixture<'s>(
        function_rva: usize,
        code: &[u8],
        symbols: &'s PdbSymbols,
        relocations: &mut BTreeMap<usize, RelocKind<'s>>,
    ) -> Vec<u8> {
        let mut coff_data = vec![0; function_rva + code.len()];
        coff_data[function_rva..].copy_from_slice(code);
        resolve_code_relocations(
            0x0040_0000,
            function_rva,
            code.len(),
            symbols,
            &coff_data,
            relocations,
            &RelocAliasManifest::default(),
            &mut RelocAliasObservations::default(),
            &DataManifest::default(),
            ManifestCoverage::AllowPartial { fences: &[] },
            WritableExtent::all_initialized(),
            CodeRelocationRecovery::RetainedOnly,
            &mut HashMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn inline_jump_table_does_not_swallow_the_next_call() {
        let function_rva = 0x1000;
        let callee_rva = 0x2000;
        // ret; a one-entry jump table holding label 5 (already rewritten to
        // the label's offset); call callee; ret. Decoded as code, the entry
        // `05 00 00 00` is `add eax, imm32` and swallows the call's opcode.
        let code = [
            0xc3, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0xc3,
        ];
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"owner"[..]),
                Some(code.len()),
            )
            .unwrap();
        symbols
            .add_function_at_rva(callee_rva, RawString::from(&b"callee"[..]), Some(1))
            .unwrap();
        let mut relocations = BTreeMap::new();
        relocations.insert(
            function_rva + 1,
            RelocKind::Function {
                overloads: symbols.functions[&function_rva].as_slice(),
                symbol: None,
                encoding: RelocationEncoding::Absolute,
            },
        );

        let resolved = resolve_fixture(function_rva, &code, &symbols, &mut relocations);
        assert_eq!(&resolved[5..10], [0xe8, 0, 0, 0, 0]);
        let RelocKind::Function {
            overloads,
            encoding: RelocationEncoding::Relative,
            ..
        } = relocations[&(function_rva + 6)]
        else {
            panic!("expected the call to be relocated");
        };
        assert_eq!(overloads[0].as_bytes(), b"callee");
    }

    #[test]
    fn code_after_a_jump_table_reached_by_a_later_branch_is_decoded() {
        let function_rva = 0x1000;
        let callee_rva = 0x2000;
        // jmp 0xc; table [0xc]; 6: call callee; ret; c: jmp 6; ret. Only the
        // branch after the table shows that offset 6 is code.
        let code = [
            0xeb, 0x0a, 0x0c, 0x00, 0x00, 0x00, 0xe8, 0xf5, 0x0f, 0x00, 0x00, 0xc3, 0xeb, 0xf8,
            0xc3,
        ];
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"owner"[..]),
                Some(code.len()),
            )
            .unwrap();
        symbols
            .add_function_at_rva(callee_rva, RawString::from(&b"callee"[..]), Some(1))
            .unwrap();
        let mut relocations = BTreeMap::new();
        relocations.insert(
            function_rva + 2,
            RelocKind::Function {
                overloads: symbols.functions[&function_rva].as_slice(),
                symbol: None,
                encoding: RelocationEncoding::Absolute,
            },
        );

        let resolved = resolve_fixture(function_rva, &code, &symbols, &mut relocations);
        assert_eq!(&resolved[6..11], [0xe8, 0, 0, 0, 0]);
        assert!(matches!(
            relocations[&(function_rva + 7)],
            RelocKind::Function {
                encoding: RelocationEncoding::Relative,
                ..
            }
        ));
    }

    #[test]
    fn an_operand_addressing_the_index_table_is_not_a_label() {
        let function_rva = 0x1000;
        let callee_rva = 0x2000;
        // 0: mov cl, [eax+0x11]; 6: jmp [ecx*4+0xd]; d: table [0x12];
        // 11: index table [0x2d]; 12: call callee; ret. Resuming at the index
        // table would decode `sub eax, imm32` over the call.
        let code = [
            0x8a, 0x88, 0x11, 0x00, 0x00, 0x00, 0xff, 0x24, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x12,
            0x00, 0x00, 0x00, 0x2d, 0xe8, 0xe9, 0x0f, 0x00, 0x00, 0xc3,
        ];
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"owner"[..]),
                Some(code.len()),
            )
            .unwrap();
        symbols
            .add_function_at_rva(callee_rva, RawString::from(&b"callee"[..]), Some(1))
            .unwrap();
        let mut relocations = BTreeMap::new();
        for site in [2, 9, 0xd] {
            relocations.insert(
                function_rva + site,
                RelocKind::Function {
                    overloads: symbols.functions[&function_rva].as_slice(),
                    symbol: None,
                    encoding: RelocationEncoding::Absolute,
                },
            );
        }

        let resolved = resolve_fixture(function_rva, &code, &symbols, &mut relocations);
        assert_eq!(&resolved[0x12..0x17], [0xe8, 0, 0, 0, 0]);
        assert!(matches!(
            relocations[&(function_rva + 0x13)],
            RelocKind::Function {
                encoding: RelocationEncoding::Relative,
                ..
            }
        ));
    }

    #[test]
    fn recursive_call_is_relocated_against_its_own_function() {
        let function_rva = 0x1000;
        // call self; ret
        let code = [0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3];
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(
                function_rva,
                RawString::from(&b"recurse"[..]),
                Some(code.len()),
            )
            .unwrap();
        let mut relocations = BTreeMap::new();

        let resolved = resolve_fixture(function_rva, &code, &symbols, &mut relocations);
        assert_eq!(resolved, [0xe8, 0, 0, 0, 0, 0xc3]);
        assert!(matches!(
            relocations[&(function_rva + 1)],
            RelocKind::Function {
                encoding: RelocationEncoding::Relative,
                ..
            }
        ));
    }

    #[test]
    fn identical_function_records_are_claimed_once_per_owner_and_rva() {
        let mut claims = FunctionClaims::default();
        assert!(claims.claim(b"SOURCE\\font.cpp", 0x401000, 0x30).unwrap());
        assert!(!claims.claim(b"SOURCE\\font.cpp", 0x401000, 0x30).unwrap());
        assert!(claims.claim(b"SOURCE\\other.cpp", 0x401000, 0x30).unwrap());
        assert!(claims.claim(b"SOURCE\\font.cpp", 0x402000, 0x30).unwrap());
    }

    #[test]
    fn identical_function_records_emit_one_body() {
        let mut claims = FunctionClaims::default();
        let mut output = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let name = RawString::from(&b"real_a"[..]);
        for _ in 0..2 {
            if claims.claim(b"SOURCE\\font.cpp", 0x401000, 1).unwrap() {
                output.add_function(name, &[0xc3]).unwrap();
            }
        }

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(
            object.section_by_name(".text").unwrap().data(),
            Ok(&[0xc3, 0x90, 0x90, 0x90][..])
        );
        assert_eq!(
            object
                .symbols()
                .filter(|symbol| symbol.is_definition() && symbol.name() == Ok("real_a"))
                .count(),
            1
        );
    }

    #[test]
    fn function_records_with_different_sizes_are_rejected() {
        let mut claims = FunctionClaims::default();
        assert!(claims.claim(b"SOURCE\\font.cpp", 0x401000, 0x30).unwrap());
        let error = claims
            .claim(b"SOURCE\\font.cpp", 0x401000, 0x34)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("SOURCE\\font.cpp at RVA 0x401000: 48 and 52"));
    }

    fn section_definition_checksums(bytes: &[u8]) -> Vec<u32> {
        use object::endian::LittleEndian;

        let coff = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)
            .unwrap();
        coff.coff_symbol_table()
            .iter()
            .filter(|(_, symbol)| {
                symbol.storage_class == object::pe::IMAGE_SYM_CLASS_STATIC
                    && symbol.number_of_aux_symbols == 1
                    && symbol.value.get(LittleEndian) == 0
                    && symbol.typ.get(LittleEndian) == object::pe::IMAGE_SYM_TYPE_NULL
                    && symbol.section_number.get(LittleEndian) > 0
            })
            .map(|(index, _)| {
                coff.coff_symbol_table()
                    .aux_section(index)
                    .unwrap()
                    .check_sum
                    .get(LittleEndian)
            })
            .collect()
    }

    fn short_coff_symbol_type(bytes: &[u8], name: &[u8]) -> u16 {
        use object::endian::LittleEndian;

        assert!(name.len() <= 8);
        let coff = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)
            .unwrap();
        let mut padded = [0_u8; 8];
        padded[..name.len()].copy_from_slice(name);
        coff.coff_symbol_table()
            .iter()
            .find(|(_, symbol)| symbol.name == padded)
            .map(|(_, symbol)| symbol.typ.get(LittleEndian))
            .unwrap()
    }

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
            provisional: false,
        }
    }

    #[test]
    fn emits_reviewed_compilation_scope() {
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
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
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let error = object
            .add_data_definition(definition(DataScope::External, 4), &[1, 2, 3, 4])
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected section offset 0x4, emitted 0x0"));
    }

    #[test]
    fn repeated_external_relocations_reuse_one_undefined_symbol() {
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let text_section_id = object.text_section();
        let offset = object.append_section_data(text_section_id, &[0; 8], 0x90);
        let name = RawString::from(&b"external"[..]);

        object
            .add_relocation(
                name,
                ObjectLocation::Extern(object::SymbolKind::Unknown),
                offset,
                RelocationEncoding::Absolute,
            )
            .unwrap();
        object
            .add_relocation(
                name,
                ObjectLocation::Extern(object::SymbolKind::Unknown),
                offset + 4,
                RelocationEncoding::Absolute,
            )
            .unwrap();

        assert_eq!(object.undefined_symbols.len(), 1);
        assert!(
            object
                .undefined_symbols
                .contains_key(b"external".as_slice())
        );
        let bytes = object.object.write().unwrap();
        assert_eq!(short_coff_symbol_type(&bytes, b"external"), 0);
    }

    #[test]
    fn conjured_targets_get_one_copy_each_and_zero_fill_is_referenced() {
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let text_section_id = object.text_section();
        let field = object.append_section_data(text_section_id, &[0; 16], 0x90);
        let mut image = vec![0_u8; 0x40];
        image[0x10..0x14].copy_from_slice(b"word");
        let relocs = BTreeMap::new();
        let reference = |object: &mut ObjectFile, kind, at| {
            object
                .add_relocation_at(
                    kind,
                    field + at,
                    &SymbolMatcher::off(),
                    &image,
                    &relocs,
                    &mut HashSet::new(),
                    TargetMaterialization::Materialize,
                )
                .unwrap();
        };
        let initialized = RelocKind::ConjuredStatic {
            symbol: RawString::from(&b"g_word"[..]),
            target_rva: 0x10,
            storage: DataStorage::Data,
        };
        let zero_fill = RelocKind::ConjuredStatic {
            symbol: RawString::from(&b"g_zero"[..]),
            target_rva: 0x30,
            storage: DataStorage::Bss,
        };
        reference(&mut object, initialized, 0);
        reference(&mut object, zero_fill, 4);
        reference(&mut object, initialized, 8);
        reference(&mut object, zero_fill, 12);

        let bytes = object.object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        let copies = parsed
            .symbols()
            .filter(|symbol| symbol.is_definition())
            .map(|symbol| {
                let section = parsed
                    .section_by_index(symbol.section_index().unwrap())
                    .unwrap();
                (
                    symbol.name().unwrap().to_owned(),
                    section.name().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(copies, [("g_word".to_owned(), ".data".to_owned())]);
        assert_eq!(parsed.section_by_name(".data").unwrap().size(), 4);
        assert!(parsed.section_by_name(".bss").is_none());
        let zero_fill = parsed
            .symbols()
            .filter(|symbol| symbol.name() == Ok("g_zero"))
            .collect::<Vec<_>>();
        assert_eq!(zero_fill.len(), 1);
        assert!(zero_fill[0].is_undefined());
    }

    #[test]
    fn conjured_static_binds_to_a_common_symbol_of_its_object() {
        let mut output = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        output.add_common_symbol(b"guard", 1).unwrap();
        assert!(output.add_common_symbol(b"guard", 1).is_err());
        let text_section_id = output.text_section();
        let field = output.append_section_data(text_section_id, &[0; 4], 0x90);
        output
            .add_relocation_at(
                RelocKind::ConjuredStatic {
                    symbol: RawString::from(&b"guard"[..]),
                    target_rva: 0x100,
                    storage: DataStorage::Data,
                },
                field,
                &SymbolMatcher::off(),
                &[0; 0x104],
                &BTreeMap::new(),
                &mut HashSet::new(),
                TargetMaterialization::Materialize,
            )
            .unwrap();

        let bytes = output.object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(parsed.section_by_name(".data").unwrap().size(), 0);
        let guard = parsed
            .symbols()
            .filter(|symbol| symbol.name() == Ok("guard"))
            .collect::<Vec<_>>();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].section(), object::SymbolSection::Common);
        assert_eq!(guard[0].size(), 1);
        let (_, relocation) = parsed
            .section_by_name(".text")
            .unwrap()
            .relocations()
            .next()
            .unwrap();
        assert_eq!(
            relocation.target(),
            object::RelocationTarget::Symbol(guard[0].index())
        );
    }

    #[test]
    fn absolute_function_reference_uses_coff_function_type() {
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let text_section_id = object.text_section();
        let field = object.append_section_data(text_section_id, &[0; 4], 0x90);
        object
            .add_relocation(
                RawString::from(&b"fn_ptr"[..]),
                ObjectLocation::Extern(object::SymbolKind::Text),
                field,
                RelocationEncoding::Absolute,
            )
            .unwrap();

        let bytes = object.object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        let symbol = parsed
            .symbols()
            .find(|symbol| symbol.name() == Ok("fn_ptr"))
            .unwrap();
        assert!(symbol.is_undefined());
        assert_eq!(symbol.kind(), object::SymbolKind::Text);
        assert_eq!(short_coff_symbol_type(&bytes, b"fn_ptr"), 0x20);
    }

    #[test]
    fn forward_function_definition_upgrades_relocation_symbol_in_place() {
        let mut output = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let text_section_id = output.text_section();
        let field = output.append_section_data(text_section_id, &[0; 4], 0x90);
        let name = RawString::from(&b"later_function"[..]);
        output
            .add_relocation(
                name,
                ObjectLocation::Extern(object::SymbolKind::Text),
                field,
                RelocationEncoding::Relative,
            )
            .unwrap();

        let undefined_id = output.undefined_symbols[b"later_function".as_slice()];
        let definition = output.add_function(name, &[0xc3]).unwrap();
        let symbol = output.object.symbol(undefined_id);
        assert_eq!(symbol.value, definition.offset);
        assert_eq!(symbol.kind, object::SymbolKind::Text);
        assert_eq!(symbol.scope, object::SymbolScope::Linkage);
        assert_eq!(
            symbol.section,
            object::write::SymbolSection::Section(definition.section_id)
        );
        assert!(
            !output
                .undefined_symbols
                .contains_key(b"later_function".as_slice())
        );

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let matching = object
            .symbols()
            .filter(|symbol| symbol.name() == Ok("later_function"))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert!(matching[0].is_definition());
        let relocation = object
            .section_by_name(".text")
            .unwrap()
            .relocations()
            .next()
            .unwrap();
        let object::RelocationTarget::Symbol(symbol) = relocation.1.target() else {
            panic!("function relocation must target a symbol");
        };
        let target = object.symbol_by_index(symbol).unwrap();
        assert_eq!(target.name(), Ok("later_function"));
        assert!(target.is_definition());
        assert_eq!(target.address(), definition.offset);
    }

    #[test]
    fn function_definition_rejects_pre_existing_defined_symbol() {
        let mut output = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let data_section_id = output.data_section();
        let name = RawString::from(&b"collision"[..]);
        output.object.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 4,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(data_section_id),
            flags: object::SymbolFlags::None,
        });

        let error = output
            .add_function(name, &[0xc3])
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("incompatible pre-existing function symbol collision"));

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let matching = object
            .symbols()
            .filter(|symbol| symbol.name() == Ok("collision"))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].kind(), object::SymbolKind::Data);
    }

    #[test]
    fn same_named_function_bodies_keep_separate_definitions() {
        let mut output = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let name = RawString::from(&b"`outer'::`1'::Local::Process"[..]);
        let first = output.add_function(name, &[0xc3]).unwrap();
        let second = output.add_function(name, &[0x90, 0xc3]).unwrap();
        assert_ne!(first.offset, second.offset);

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let offsets = object
            .symbols()
            .filter(|symbol| symbol.name() == Ok("`outer'::`1'::Local::Process"))
            .map(|symbol| (symbol.is_definition(), symbol.address()))
            .collect::<Vec<_>>();
        assert_eq!(offsets, [(true, first.offset), (true, second.offset)]);
    }

    #[test]
    fn repeated_conjured_targets_share_one_private_copy() {
        let mut object = ObjectFile::empty_with_topology(false, SectionTopology::Synthesized);
        let text_section_id = object.text_section();
        let field = object.append_section_data(text_section_id, &[0; 16], 0x90);
        let mut image = vec![0_u8; 0x40];
        image[0x10..0x14].copy_from_slice(b"word");
        let relocs = BTreeMap::new();
        let constant = RelocKind::ConjuredConstant {
            symbol: RawString::from(&b"g_word"[..]),
            target_rva: 0x10,
        };
        let string = RelocKind::ConjuredString {
            symbol: RawString::from(&b"??_C@_03ABC@D?$AA@"[..]),
            data: b"D\0",
        };
        for (kind, at) in [(constant, 0), (string, 4), (constant, 8), (string, 12)] {
            object
                .add_relocation_at(
                    kind,
                    field + at,
                    &SymbolMatcher::off(),
                    &image,
                    &relocs,
                    &mut HashSet::new(),
                    TargetMaterialization::Materialize,
                )
                .unwrap();
        }

        let bytes = object.object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        let copies = parsed
            .symbols()
            .filter(|symbol| symbol.is_definition())
            .map(|symbol| symbol.name().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(copies, ["g_word", "D_"]);
        assert_eq!(parsed.section_by_name(".rdata").unwrap().size(), 8);
        let targets = parsed
            .section_by_name(".text")
            .unwrap()
            .relocations()
            .map(|(_, relocation)| relocation.target())
            .collect::<Vec<_>>();
        assert_eq!(targets.len(), 4);
        assert_eq!((targets[0], targets[1]), (targets[2], targets[3]));
    }

    #[test]
    fn emits_distinct_data_sections() {
        let sections = [
            DataSection {
                object: b"fixture.c",
                ordinal: 1,
                name: b".drectve",
                rva: None,
                size: 0,
                alignment: 1,
                characteristics: 0x0010_0a00,
                checksum: 0,
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
                checksum: 0,
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
                characteristics: 0xc030_0040,
                checksum: 0,
                comdat_selection: ComdatSelection::None,
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
                        provisional: false,
                    },
                    &image,
                )
                .unwrap();
        }

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let parsed_sections = object.sections().collect::<Vec<_>>();
        assert_eq!(parsed_sections[0].name().unwrap(), ".drectve");
        assert_eq!(parsed_sections[1].data().unwrap(), b"main");
        assert_eq!(parsed_sections[2].data().unwrap(), b"fold");
    }

    #[test]
    fn rdata_padding_applies_only_to_sections_the_delinker_creates() {
        let mut lazy = ObjectFile::empty_with_topology(true, SectionTopology::Exact);
        let rdata = lazy.rdata_section();
        assert_eq!(lazy.append_section_data(rdata, b"text", 0).offset, 4);

        let reviewed = [DataSection {
            object: b"fixture.c",
            ordinal: 1,
            name: b".rdata",
            rva: Some(0x10),
            size: 8,
            alignment: 4,
            characteristics: 0x4030_0040,
            checksum: 0,
            comdat_selection: ComdatSelection::None,
            associative_ordinal: None,
            storage: Some(SectionStorage::Rdata),
        }];
        let image = vec![0x55_u8; 0x20];
        let section = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 2,
            data: &image,
        };
        let output = ObjectFile::with_sections(&reviewed, section, section, &image, true).unwrap();
        let bytes = output.object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(parsed.section_by_name(".rdata").unwrap().size(), 8);
    }

    #[test]
    fn placed_sections_find_any_overlap() {
        let section = |ordinal, rva, size| DataSection {
            object: b"fixture.c",
            ordinal,
            name: b".data",
            rva,
            size,
            alignment: 4,
            characteristics: 0xc030_0040,
            checksum: 0,
            comdat_selection: ComdatSelection::None,
            associative_ordinal: None,
            storage: Some(SectionStorage::Data),
        };
        let sections = [
            section(1, Some(0x100), 0x100),
            section(2, Some(0x210), 0x10),
            section(3, None, 0x40),
        ];
        let placed = PlacedSections::new(&sections);
        assert_eq!(placed.overlapping(0x1fc, 0x204).unwrap().ordinal, 1);
        assert_eq!(placed.overlapping(0x20c, 0x214).unwrap().ordinal, 2);
        assert!(placed.overlapping(0x200, 0x210).is_none());
        assert!(placed.overlapping(0x0, 0x100).is_none());
        assert!(placed.overlapping(0x220, 0x300).is_none());
    }

    #[test]
    fn emits_comdat_groups_with_their_associative_sections() {
        use object::ObjectComdat as _;

        let section =
            |ordinal, name: &'static [u8], rva, characteristics, selection, leader| DataSection {
                object: b"fixture.c",
                ordinal,
                name,
                rva,
                size: 4,
                alignment: 4,
                characteristics,
                checksum: 0,
                comdat_selection: selection,
                associative_ordinal: leader,
                storage: rva.map(|_| SectionStorage::Rdata),
            };
        let sections = [
            section(
                1,
                b".rdata",
                Some(0x10),
                0x4030_0040,
                ComdatSelection::None,
                None,
            ),
            section(
                2,
                b".rdata$r",
                Some(0x20),
                0x4030_1040,
                ComdatSelection::Any,
                None,
            ),
            section(
                3,
                b".rdata",
                Some(0x30),
                0x4030_1040,
                ComdatSelection::Largest,
                None,
            ),
            section(
                4,
                b".debug$F",
                None,
                0x4230_1040,
                ComdatSelection::Associative,
                Some(2),
            ),
        ];
        let image = vec![0_u8; 0x40];
        let rdata = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 2,
            data: &image,
        };
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 3,
            data: &[],
        };
        let mut output = ObjectFile::with_sections(&sections, rdata, empty, &image, false).unwrap();
        // Before any definition, neither COMDAT has a symbol of its own.
        assert_eq!(
            symbolless_comdats(&output.object.write().unwrap()).unwrap(),
            2
        );
        for (name, rva, ordinal) in [
            (&b"??_R4x@@6B@"[..], 0x20, 2),
            (&b"??_7x@@6B@"[..], 0x30, 3),
        ] {
            output
                .add_data_definition(
                    DataDefinition {
                        symbol_name: RawString::from(name),
                        object: b"fixture.c",
                        rva,
                        size: 4,
                        storage: DataStorage::Rdata,
                        alignment: 4,
                        section_ordinal: Some(ordinal),
                        section_offset: Some(0),
                        scope: DataScope::External,
                        provisional: false,
                    },
                    &image,
                )
                .unwrap();
        }

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let mut comdats = object
            .comdats()
            .map(|comdat| {
                (
                    comdat.kind(),
                    comdat.sections().map(|index| index.0).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        comdats.sort_by_key(|(_, sections)| sections[0]);
        assert_eq!(symbolless_comdats(&bytes).unwrap(), 0);
        assert_eq!(
            comdats,
            [
                (object::ComdatKind::Any, vec![2, 4]),
                (object::ComdatKind::Largest, vec![3]),
            ]
        );
        let associative = object.section_by_index(object::SectionIndex(4)).unwrap();
        let object::SectionFlags::Coff { characteristics } = associative.flags() else {
            panic!("COFF section flags");
        };
        assert_ne!(characteristics & object::pe::IMAGE_SCN_LNK_COMDAT, 0);
    }

    #[test]
    fn unplaced_data_never_joins_a_comdat_or_grouped_section() {
        let section = |ordinal, name: &'static [u8], rva, characteristics, selection| DataSection {
            object: b"fixture.c",
            ordinal,
            name,
            rva: Some(rva),
            size: 4,
            alignment: 4,
            characteristics,
            checksum: 0,
            comdat_selection: selection,
            associative_ordinal: None,
            storage: Some(SectionStorage::Data),
        };
        let sections = [
            section(1, b".data", 0x10, 0xc030_1040, ComdatSelection::Any),
            section(2, b".CRT$XCU", 0x20, 0xc030_0040, ComdatSelection::None),
            section(3, b".data", 0x30, 0xc030_0040, ComdatSelection::None),
        ];
        let image = vec![0_u8; 0x40];
        let data = crate::SecInfo {
            rva: 0,
            va: 0,
            size: image.len(),
            id: 3,
            data: &image,
        };
        let mut output = ObjectFile::with_sections(&sections, data, data, &image, false).unwrap();
        assert_eq!(output.data_section(), output.topology_sections[2].id);

        let mut output =
            ObjectFile::with_sections(&sections[..2], data, data, &image, false).unwrap();
        let sink = output.data_section();
        assert!(
            output
                .topology_sections
                .iter()
                .all(|section| section.id != sink),
            "unplaced data joined a manifest section"
        );
    }

    #[test]
    fn exact_topology_does_not_invent_empty_sections() {
        let sections = [DataSection {
            object: b"SOURCE\\only_code.c",
            ordinal: 1,
            name: b".text",
            rva: None,
            size: 0,
            alignment: 16,
            characteristics: 0x6050_0020,
            checksum: 0,
            comdat_selection: ComdatSelection::None,
            associative_ordinal: None,
            storage: None,
        }];
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 0,
            data: &[],
        };
        let mut output = ObjectFile::with_sections(&sections, empty, empty, &[], false).unwrap();
        output
            .add_function(RawString::from(&b"only_code"[..]), &[0xc3])
            .unwrap();

        let bytes = output.object.write().unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(
            object
                .sections()
                .map(|section| section.name().unwrap().to_owned())
                .collect::<Vec<_>>(),
            [".text"]
        );
    }

    #[test]
    fn overrides_only_manifest_declared_section_definition_checksums() {
        let sections = [DataSection {
            object: b"SOURCE\\only_code.c",
            ordinal: 1,
            name: b".text",
            rva: None,
            size: 1,
            alignment: 1,
            characteristics: 0x6010_0020,
            checksum: 0x1234_5678,
            comdat_selection: ComdatSelection::None,
            associative_ordinal: None,
            storage: None,
        }];
        let empty = crate::SecInfo {
            rva: 0,
            va: 0,
            size: 0,
            id: 0,
            data: &[],
        };
        let mut output = ObjectFile::with_sections(&sections, empty, empty, &[], false).unwrap();
        output
            .add_function(RawString::from(&b"only_code"[..]), &[0xc3])
            .unwrap();
        let lazy_rdata = output.rdata_section();
        output
            .object
            .append_section_data(lazy_rdata, &[1, 2, 3, 4], 4);
        output.object.section_symbol(lazy_rdata);

        let reviewed = output.reviewed_section_checksums.clone();
        let mut bytes = output.object.write().unwrap();
        let generated = section_definition_checksums(&bytes);
        assert_eq!(generated.len(), 2);
        assert_ne!(generated[0], 0x1234_5678);
        let lazy_generated = generated[1];
        assert_eq!(
            apply_reviewed_section_checksums(&mut bytes, &reviewed).unwrap(),
            1
        );
        assert_eq!(
            section_definition_checksums(&bytes),
            [0x1234_5678, lazy_generated]
        );

        assert_eq!(zero_section_checksums(&mut bytes).unwrap(), 2);
        assert_eq!(section_definition_checksums(&bytes), [0, 0]);
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
            checksum: 0,
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
                provisional: false,
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
                provisional: false,
            },
        ];
        let mut output = ObjectFile::with_sections(&sections, empty, data, &image, false).unwrap();
        for definition in definitions {
            output.add_data_definition(definition, &image).unwrap();
        }

        let mut relocs = BTreeMap::new();
        relocs.insert(
            0x34,
            RelocKind::ConjuredStatic {
                symbol: RawString::from(&b"external"[..]),
                target_rva: 0x40,
                storage: DataStorage::Data,
            },
        );
        output
            .add_topology_section_relocations(&SymbolMatcher::off(), &image, &relocs)
            .unwrap();
        for definition in definitions {
            assert!(!output.definition_uses_affine_topology(definition));
            output
                .add_data_relocations(definition, &SymbolMatcher::off(), &image, &relocs)
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
            checksum: 0,
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
            provisional: false,
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
                characteristics: 0xc030_0040,
                checksum: 0,
                comdat_selection: ComdatSelection::None,
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
                characteristics: 0xc030_0040,
                checksum: 0,
                comdat_selection: ComdatSelection::None,
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
                        provisional: false,
                    },
                    &image,
                )
                .unwrap();
        }

        let mut relocs = BTreeMap::new();
        relocs.insert(
            0x14,
            RelocKind::ConjuredStatic {
                symbol: RawString::from(&b"external"[..]),
                target_rva: 0x18,
                storage: DataStorage::Data,
            },
        );
        output
            .add_topology_section_relocations(&SymbolMatcher::off(), &image, &relocs)
            .unwrap();

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
            checksum: 0,
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
                    provisional: false,
                },
                &image,
            )
            .unwrap_err();
        assert!(error.to_string().contains("exceeds its assigned section"));
    }
}
