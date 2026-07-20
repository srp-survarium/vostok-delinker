use crate::Env;
use crate::data_manifest::DataManifest;
use crate::pdb_symbols::{self, FunctionRelocationField, PdbDataSymbol};
use crate::reloc_alias_manifest::{RelocAliasManifest, RelocAliasObservations};
use crate::utils::ToUsize;

use pdb2::RawString;

use object::LittleEndian;
use object::{Object, ObjectSection};

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
pub enum RelocKind<'a> {
    Import {
        symbol: RawString<'static>,
    },

    // .text
    Function {
        overloads: &'a [RawString<'static>],
        symbol: Option<RawString<'static>>,
        encoding: RelocationEncoding,
    },

    // .rdata
    ConstantString {
        symbol: RawString<'static>,
        data: &'a [u8],
    },
    Constant {
        symbol: RawString<'static>,
        target_rva: usize,
    },

    // .data
    Static {
        symbol: RawString<'static>,
        target_rva: usize,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RelocationEncoding {
    Absolute,
    Relative,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ManifestCoverage {
    AllowPartial,
    RequireComplete,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BaseRelocationSource {
    Directory { rva: u32, size: u32 },
    Stripped,
    Absent,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodeRelocationRecovery {
    RetainedOnly,
    ExactPdbInstructionOperands,
}

impl BaseRelocationSource {
    pub fn code_relocation_recovery(self) -> CodeRelocationRecovery {
        match self {
            Self::Stripped => CodeRelocationRecovery::ExactPdbInstructionOperands,
            Self::Directory { .. } | Self::Absent => CodeRelocationRecovery::RetainedOnly,
        }
    }
}

pub struct ResolvedRelocations<'a> {
    pub coff_data: Vec<u8>,
    pub by_rva: BTreeMap<usize, RelocKind<'a>>,
    pub observed_aliases: RelocAliasObservations,
    pub source: BaseRelocationSource,
}

fn resolve_manifest_alias(
    aliases: &RelocAliasManifest,
    owners: &BTreeMap<usize, PdbDataSymbol>,
    symbols: &pdb_symbols::PdbSymbols,
    observed: &mut RelocAliasObservations,
    reloc_rva: usize,
    target_rva: usize,
) -> anyhow::Result<Option<(u32, RawString<'static>)>> {
    let FunctionRelocationField::Within { function_rva } =
        symbols.relocation_field_owner(reloc_rva)
    else {
        return Ok(None);
    };
    let Some(alias) = aliases.resolve(function_rva, target_rva, reloc_rva, observed) else {
        return Ok(None);
    };

    let mut owners = owners
        .iter()
        .filter(|(_, symbol)| symbol.name == alias.owner);
    let Some((owner_rva, _)) = owners.next() else {
        anyhow::bail!(
            "relocation alias owner is absent from the PDB: {}",
            alias.owner
        );
    };
    if owners.next().is_some() {
        anyhow::bail!(
            "relocation alias owner is ambiguous in the PDB: {}",
            alias.owner
        );
    }
    if (*owner_rva as u32).wrapping_add(alias.addend) != target_rva as u32 {
        anyhow::bail!("relocation alias owner/addend does not resolve to target");
    }

    Ok(Some((alias.addend, alias.owner)))
}

#[derive(Copy, Clone)]
enum ExactPdbDataTarget<'a> {
    ConstantString {
        symbol: RawString<'static>,
        data: &'a [u8],
    },
    Constant {
        symbol: RawString<'static>,
    },
    Static {
        symbol: RawString<'static>,
    },
}

pub(crate) fn classify_exact_pdb_target<'s>(
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    reloc_aliases: &RelocAliasManifest,
    observed_aliases: &mut RelocAliasObservations,
    manifest_coverage: ManifestCoverage,
    owner_function_rva: usize,
    reloc_rva: usize,
    target_rva: usize,
) -> anyhow::Result<Option<(RelocKind<'s>, u32)>> {
    if let Some(symbol) = symbols.imports.get(&target_rva) {
        return Ok(Some((RelocKind::Import { symbol: *symbol }, 0)));
    }
    if let Some(overloads) = symbols.functions.get(&target_rva) {
        let symbol = reloc_aliases.resolve_function_alias(
            owner_function_rva,
            target_rva,
            reloc_rva,
            overloads,
            observed_aliases,
        )?;
        return Ok(Some((
            RelocKind::Function {
                overloads,
                symbol,
                encoding: RelocationEncoding::Absolute,
            },
            0,
        )));
    }

    let exact = if let Some((symbol, data)) = symbols.strings.get(&target_rva) {
        Some(ExactPdbDataTarget::ConstantString {
            symbol: *symbol,
            data,
        })
    } else if let Some(symbol) = symbols.constants.get(&target_rva) {
        Some(ExactPdbDataTarget::Constant {
            symbol: symbol.name,
        })
    } else {
        symbols
            .statics
            .get(&target_rva)
            .map(|symbol| ExactPdbDataTarget::Static {
                symbol: symbol.name,
            })
    };
    let Some(exact) = exact else {
        return Ok(None);
    };

    let (owners, is_static) = match exact {
        ExactPdbDataTarget::ConstantString { .. } | ExactPdbDataTarget::Constant { .. } => {
            (&symbols.constants, false)
        }
        ExactPdbDataTarget::Static { .. } => (&symbols.statics, true),
    };
    if let Some((addend, owner)) = resolve_manifest_alias(
        reloc_aliases,
        owners,
        symbols,
        observed_aliases,
        reloc_rva,
        target_rva,
    )? {
        let kind = if is_static {
            RelocKind::Static {
                symbol: owner,
                target_rva,
            }
        } else {
            RelocKind::Constant {
                symbol: owner,
                target_rva,
            }
        };
        return Ok(Some((kind, addend)));
    }

    if let Some((owner, addend)) = data_manifest.owner_and_addend_for_rva(target_rva) {
        let addend = u32::try_from(addend)?;
        let kind = if is_static {
            RelocKind::Static {
                symbol: owner.symbol_name,
                target_rva,
            }
        } else {
            RelocKind::Constant {
                symbol: owner.symbol_name,
                target_rva,
            }
        };
        return Ok(Some((kind, addend)));
    }

    if manifest_coverage == ManifestCoverage::RequireComplete {
        anyhow::bail!(
            "--strict: recovered instruction relocation at RVA {reloc_rva:#x} targets data RVA {target_rva:#x}, which is not covered by the data manifest"
        );
    }

    Ok(Some(match exact {
        ExactPdbDataTarget::ConstantString { symbol, data } => {
            (RelocKind::ConstantString { symbol, data }, 0)
        }
        ExactPdbDataTarget::Constant { symbol } => (RelocKind::Constant { symbol, target_rva }, 0),
        ExactPdbDataTarget::Static { symbol } => (RelocKind::Static { symbol, target_rva }, 0),
    }))
}

#[repr(C)]
#[derive(bytemuck::AnyBitPattern, bytemuck::NoUninit, Copy, Clone)]
struct RelocHeader {
    page_rva: u32,
    block_size: u32,
}
const HEADER_SIZE: usize = std::mem::size_of::<RelocHeader>();

#[repr(C)]
#[derive(bytemuck::AnyBitPattern, bytemuck::NoUninit, Copy, Clone)]
struct RelocEntry {
    entry: u16,
}

#[derive(Copy, Clone)]
struct RawSectionExtent {
    rva: u32,
    file_offset: u32,
    file_size: u32,
}

fn checked_directory_file_range<I>(
    rva: u32,
    size: u32,
    sections: I,
    file_size: usize,
) -> anyhow::Result<std::ops::Range<usize>>
where
    I: IntoIterator<Item = RawSectionExtent>,
{
    let end_rva = rva
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("base relocation directory RVA extent overflows"))?;
    for section in sections {
        let Some(raw_end) = section.rva.checked_add(section.file_size) else {
            continue;
        };
        if section.rva <= rva && end_rva <= raw_end {
            let section_offset = rva - section.rva;
            let file_start = section
                .file_offset
                .checked_add(section_offset)
                .ok_or_else(|| anyhow::anyhow!("base relocation directory file offset overflows"))?
                as usize;
            let file_end = file_start.checked_add(size as usize).ok_or_else(|| {
                anyhow::anyhow!("base relocation directory file extent overflows")
            })?;
            anyhow::ensure!(
                file_end <= file_size,
                "base relocation directory extends beyond the PE file"
            );
            return Ok(file_start..file_end);
        }
    }
    anyhow::bail!("base relocation directory is not contained in one raw-backed PE section")
}

fn normalize_base_relocation_directory(
    directory: Option<(u32, u32)>,
) -> anyhow::Result<Option<(u32, u32)>> {
    match directory {
        None | Some((0, 0)) => Ok(None),
        Some((0, _)) => anyhow::bail!("base relocation directory has a size but no RVA"),
        Some((_, 0)) => anyhow::bail!("base relocation directory has an RVA but no size"),
        Some(directory) => Ok(Some(directory)),
    }
}

fn classify_base_relocation_source(
    directory: Option<(u32, u32)>,
    characteristics: u16,
) -> BaseRelocationSource {
    match directory {
        Some((rva, size)) => BaseRelocationSource::Directory { rva, size },
        None if characteristics & object::pe::IMAGE_FILE_RELOCS_STRIPPED != 0 => {
            BaseRelocationSource::Stripped
        }
        None => BaseRelocationSource::Absent,
    }
}

fn base_relocation_data(
    exe: &'static object::read::pe::PeFile32<'static>,
) -> anyhow::Result<(BaseRelocationSource, &'static [u8])> {
    let characteristics = exe
        .nt_headers()
        .file_header
        .characteristics
        .get(LittleEndian);
    let directory = exe
        .data_directories()
        .iter()
        .nth(object::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .map(|directory| {
            (
                directory.virtual_address.get(LittleEndian),
                directory.size.get(LittleEndian),
            )
        });
    let directory = normalize_base_relocation_directory(directory)?;
    let source = classify_base_relocation_source(directory, characteristics);
    let BaseRelocationSource::Directory { rva, size } = source else {
        return Ok((source, &[]));
    };
    let range = checked_directory_file_range(
        rva,
        size,
        exe.section_table().iter().map(|section| RawSectionExtent {
            rva: section.virtual_address.get(LittleEndian),
            file_offset: section.pointer_to_raw_data.get(LittleEndian),
            file_size: section.size_of_raw_data.get(LittleEndian),
        }),
        exe.data().len(),
    )?;
    Ok((
        BaseRelocationSource::Directory { rva, size },
        &exe.data()[range],
    ))
}

pub fn resolve_absolute_relocations<'s>(
    env: &Env,
    exe: &'static object::read::pe::PeFile32<'static>,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
) -> anyhow::Result<ResolvedRelocations<'s>> {
    let (source, reloc_data) = base_relocation_data(exe)?;

    let exe_data = map_pe_image(exe);
    let mut coff_data = exe_data.clone();
    let mut relocs_rva = BTreeMap::<usize, RelocKind>::new();
    let mut observed_aliases = RelocAliasObservations::default();
    let mut skipped_sized_constants = 0usize;
    let mut skipped_sized_statics = 0usize;

    let mut pos = 0;
    while pos + HEADER_SIZE <= reloc_data.len() {
        let RelocHeader {
            page_rva,
            block_size,
        } = bytemuck::pod_read_unaligned::<RelocHeader>(&reloc_data[pos..pos + HEADER_SIZE]);

        if block_size == 0 || block_size < 8 {
            break;
        }

        let entries: &[RelocEntry] =
            bytemuck::cast_slice(&reloc_data[pos + HEADER_SIZE..pos + block_size.to_usize()]);
        pos += block_size.to_usize();

        for RelocEntry { entry } in entries {
            let reloc_type = entry >> 12;
            let reloc_offset = entry & 0x0FFF;

            const RELOC_TYP_HIGHLOW: u16 = 3;

            if reloc_type != RELOC_TYP_HIGHLOW {
                continue;
            }

            // .reloc        .text/.rdata/.data  .text/.rdata/.data
            // [reloc_rva]   [target_va]         [target]
            //   |              ^    |              ^
            //   |              |    |              |
            //   +--------------+    +--------------+
            //
            // * `target_va` replaced with offset of the closest named symbol
            //
            let reloc_rva = (page_rva + u32::from(reloc_offset)).to_usize();

            let target_va =
                bytemuck::pod_read_unaligned::<u32>(&exe_data[reloc_rva..reloc_rva + 4]);
            let target_rva = (target_va - env.image_base).to_usize();

            let coff_data_reloc = &mut coff_data[reloc_rva..reloc_rva + 4];

            match () {
                () if env.iat.is_some_and(|iat| iat.contains_rva(target_rva)) => {
                    let Some(import_name) = symbols.imports.get(&target_rva) else {
                        anyhow::bail!(
                            "PE base relocation at RVA {reloc_rva:#x} targets IAT slot RVA \
                             {target_rva:#x}, which has no PDB symbol"
                        );
                    };
                    coff_data_reloc.copy_from_slice(&0_u32.to_le_bytes());
                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::Import {
                            symbol: *import_name,
                        },
                    );
                }
                () if (env.text.rva..env.text.rva + env.text.size).contains(&target_rva) => {
                    let (function_rva, function_overloads) = symbols
                        .functions
                        .range(..=target_rva)
                        .next_back()
                        .expect("all function relocs to be named");

                    let diff = u32::try_from(target_rva - *function_rva)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                    let symbol = if diff == 0
                        && (env.text.rva..env.text.rva + env.text.size).contains(&reloc_rva)
                    {
                        match symbols.relocation_field_owner(reloc_rva) {
                            FunctionRelocationField::Within { function_rva } => reloc_aliases
                                .resolve_function_alias(
                                    function_rva,
                                    target_rva,
                                    reloc_rva,
                                    function_overloads,
                                    &mut observed_aliases,
                                )?,
                            FunctionRelocationField::MissingFunction
                            | FunctionRelocationField::UnknownExtent
                            | FunctionRelocationField::OutsideExtent
                            | FunctionRelocationField::FieldOverflow => None,
                        }
                    } else {
                        None
                    };

                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::Function {
                            overloads: function_overloads,
                            symbol,
                            encoding: RelocationEncoding::Absolute,
                        },
                    );
                }
                () if (env.rdata.rva..env.rdata.rva + env.rdata.size).contains(&target_rva) => {
                    if (env.text.rva..env.text.rva + env.text.size).contains(&reloc_rva)
                        && let Some((addend, owner)) = resolve_manifest_alias(
                            reloc_aliases,
                            &symbols.constants,
                            symbols,
                            &mut observed_aliases,
                            reloc_rva,
                            target_rva,
                        )?
                    {
                        coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Constant {
                                symbol: owner,
                                target_rva,
                            },
                        );
                        continue;
                    }
                    let owner = data_manifest.owner_and_addend_for_rva(target_rva);
                    match (manifest_coverage, owner) {
                        (_, Some((owner, addend))) => {
                            let diff = u32::try_from(addend)?;
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::Constant {
                                    symbol: owner.symbol_name,
                                    target_rva,
                                },
                            );
                        }
                        (ManifestCoverage::RequireComplete, None) => {
                            anyhow::bail!(
                                "--strict: PE base relocation at RVA {reloc_rva:#x} targets data \
                                 RVA {target_rva:#x}, which is not covered by the data manifest"
                            );
                        }
                        (ManifestCoverage::AllowPartial, None) => {
                            match symbols.strings.range(..=target_rva).next_back() {
                                Some((string_rva, (string_mangled_name, string)))
                                    if target_rva - string_rva < string.len() =>
                                {
                                    let diff = u32::try_from(target_rva - *string_rva)?;
                                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                                    relocs_rva.insert(
                                        reloc_rva,
                                        RelocKind::ConstantString {
                                            symbol: *string_mangled_name,
                                            data: string,
                                        },
                                    );
                                }

                                Some(_) | None => {
                                    let Some((constant_rva, constant)) =
                                        symbols.constants.range(..=target_rva).next_back()
                                    else {
                                        unreachable!("All constants must be named");
                                    };

                                    if !constant.contains(*constant_rva, target_rva) {
                                        skipped_sized_constants += 1;
                                        continue;
                                    }

                                    let diff = u32::try_from(target_rva - *constant_rva)?;
                                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                                    relocs_rva.insert(
                                        reloc_rva,
                                        RelocKind::Constant {
                                            symbol: constant.name,
                                            target_rva,
                                        },
                                    );
                                }
                            };
                        }
                    }
                }
                () if (env.data.rva..env.data.rva + env.data.size).contains(&target_rva) => {
                    if (env.text.rva..env.text.rva + env.text.size).contains(&reloc_rva)
                        && let Some((addend, owner)) = resolve_manifest_alias(
                            reloc_aliases,
                            &symbols.statics,
                            symbols,
                            &mut observed_aliases,
                            reloc_rva,
                            target_rva,
                        )?
                    {
                        coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Static {
                                symbol: owner,
                                target_rva,
                            },
                        );
                        continue;
                    }
                    let owner = data_manifest.owner_and_addend_for_rva(target_rva);
                    match (manifest_coverage, owner) {
                        (_, Some((owner, addend))) => {
                            let diff = u32::try_from(addend)?;
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::Static {
                                    symbol: owner.symbol_name,
                                    target_rva,
                                },
                            );
                        }
                        (ManifestCoverage::RequireComplete, None) => {
                            anyhow::bail!(
                                "--strict: PE base relocation at RVA {reloc_rva:#x} targets data \
                                 RVA {target_rva:#x}, which is not covered by the data manifest"
                            );
                        }
                        (ManifestCoverage::AllowPartial, None) => {
                            let Some((static_rva, static_symbol)) =
                                symbols.statics.range(..=target_rva).next_back()
                            else {
                                let _reloc_va = reloc_rva + env.image_base.to_usize();
                                // @TODO: There is a "single" unnamed static relocation in base, which is a
                                // string "rb\0" used for `fopen` in `ov_fopen`.
                                continue;
                            };

                            if !static_symbol.contains(*static_rva, target_rva) {
                                skipped_sized_statics += 1;
                                continue;
                            }

                            let diff = u32::try_from(target_rva - *static_rva)?;
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::Static {
                                    symbol: static_symbol.name,
                                    target_rva,
                                },
                            );
                        }
                    }
                }
                () => (),
            }
        }
    }

    if skipped_sized_constants != 0 || skipped_sized_statics != 0 {
        eprintln!(
            "[relocs] skipped {} .rdata and {} .data relocations outside known PDB symbol sizes",
            skipped_sized_constants, skipped_sized_statics
        );
    }

    Ok(ResolvedRelocations {
        coff_data,
        by_rva: relocs_rva,
        observed_aliases,
        source,
    })
}

fn map_pe_image(exe: &object::read::pe::PeFile32) -> Vec<u8> {
    let image_base = exe
        .nt_headers()
        .optional_header
        .image_base
        .get(LittleEndian)
        .to_usize();
    let image_size = exe
        .nt_headers()
        .optional_header
        .size_of_image
        .get(LittleEndian)
        .to_usize();
    let mut mapped = vec![0u8; image_size];

    for section in exe.sections() {
        let rva = section.address().to_usize() - image_base;
        if let Ok(data) = section.data() {
            mapped[rva..rva + data.len()].copy_from_slice(data);
        }
    }
    mapped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section() -> RawSectionExtent {
        RawSectionExtent {
            rva: 0x1000,
            file_offset: 0x400,
            file_size: 0x180,
        }
    }

    #[test]
    fn relocation_source_distinguishes_directory_stripped_and_absent() {
        let directory = classify_base_relocation_source(Some((0x3000, 0x80)), 0);
        let stripped =
            classify_base_relocation_source(None, object::pe::IMAGE_FILE_RELOCS_STRIPPED);
        let absent = classify_base_relocation_source(None, 0);
        assert_eq!(
            directory,
            BaseRelocationSource::Directory {
                rva: 0x3000,
                size: 0x80
            }
        );
        assert_eq!(stripped, BaseRelocationSource::Stripped);
        assert_eq!(absent, BaseRelocationSource::Absent);
        assert_eq!(
            directory.code_relocation_recovery(),
            CodeRelocationRecovery::RetainedOnly
        );
        assert_eq!(
            stripped.code_relocation_recovery(),
            CodeRelocationRecovery::ExactPdbInstructionOperands
        );
        assert_eq!(
            absent.code_relocation_recovery(),
            CodeRelocationRecovery::RetainedOnly
        );
    }

    #[test]
    fn exact_pdb_target_classifier_rejects_nearby_addresses() {
        let mut symbols = pdb_symbols::PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"exact"[..]), None)
            .unwrap();
        symbols
            .imports
            .insert(0x3000, RawString::from(&b"__imp_exact"[..]));
        let manifest = DataManifest::default();
        let aliases = RelocAliasManifest::default();
        let mut observed = RelocAliasObservations::default();

        let function = classify_exact_pdb_target(
            &symbols,
            &manifest,
            &aliases,
            &mut observed,
            ManifestCoverage::AllowPartial,
            0x1000,
            0x1010,
            0x2000,
        )
        .unwrap();
        assert!(matches!(function, Some((RelocKind::Function { .. }, 0))));
        let import = classify_exact_pdb_target(
            &symbols,
            &manifest,
            &aliases,
            &mut observed,
            ManifestCoverage::AllowPartial,
            0x1000,
            0x1014,
            0x3000,
        )
        .unwrap();
        assert!(matches!(import, Some((RelocKind::Import { .. }, 0))));
        assert!(
            classify_exact_pdb_target(
                &symbols,
                &manifest,
                &aliases,
                &mut observed,
                ManifestCoverage::AllowPartial,
                0x1000,
                0x1018,
                0x2001,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn strict_manifest_precedes_exact_pdb_data_fallback() {
        let mut symbols = pdb_symbols::PdbSymbols::default();
        symbols.statics.insert(
            0x4000,
            PdbDataSymbol::new(RawString::from(&b"exact_data"[..]), Some(4)),
        );
        let error = classify_exact_pdb_target(
            &symbols,
            &DataManifest::default(),
            &RelocAliasManifest::default(),
            &mut RelocAliasObservations::default(),
            ManifestCoverage::RequireComplete,
            0x1000,
            0x1010,
            0x4000,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("--strict"));
        assert!(error.contains("0x1010"));
        assert!(error.contains("0x4000"));
    }

    #[test]
    fn relocation_directory_requires_consistent_rva_and_size() {
        assert_eq!(normalize_base_relocation_directory(None).unwrap(), None);
        assert_eq!(
            normalize_base_relocation_directory(Some((0, 0))).unwrap(),
            None
        );
        assert!(
            normalize_base_relocation_directory(Some((0, 4)))
                .unwrap_err()
                .to_string()
                .contains("size but no RVA")
        );
        assert!(
            normalize_base_relocation_directory(Some((0x1000, 0)))
                .unwrap_err()
                .to_string()
                .contains("RVA but no size")
        );
    }

    #[test]
    fn relocation_directory_range_uses_raw_section_extent() {
        assert_eq!(
            checked_directory_file_range(0x1100, 0x20, [section()], 0x1000).unwrap(),
            0x500..0x520
        );
        let error = checked_directory_file_range(0x1170, 0x20, [section()], 0x1000)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("not contained in one raw-backed PE section"));
    }

    #[test]
    fn relocation_directory_range_rejects_rva_overflow() {
        let error = checked_directory_file_range(u32::MAX - 3, 8, [section()], usize::MAX)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("RVA extent overflows"));
    }
}
