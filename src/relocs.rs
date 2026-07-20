use crate::Env;
use crate::data_manifest::DataManifest;
use crate::pdb_symbols;
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

pub struct ResolvedRelocations<'a> {
    pub coff_data: Vec<u8>,
    pub by_rva: BTreeMap<usize, RelocKind<'a>>,
    pub observed_aliases: RelocAliasObservations,
}

fn resolve_manifest_alias(
    aliases: &RelocAliasManifest,
    symbols: &BTreeMap<usize, RawString<'static>>,
    functions: &BTreeMap<usize, Vec<RawString<'static>>>,
    observed: &mut RelocAliasObservations,
    reloc_rva: usize,
    target_rva: usize,
) -> anyhow::Result<Option<(u32, RawString<'static>)>> {
    let Some((function_rva, _)) = functions.range(..=reloc_rva).next_back() else {
        return Ok(None);
    };
    let Some(alias) = aliases.resolve(*function_rva, target_rva, reloc_rva, observed) else {
        return Ok(None);
    };

    let mut owners = symbols
        .iter()
        .filter(|(_, symbol_name)| **symbol_name == alias.owner);
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

pub fn resolve_absolute_relocations<'s>(
    env: &Env,
    exe: &'static object::read::pe::PeFile32<'static>,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
) -> anyhow::Result<ResolvedRelocations<'s>> {
    let Some(reloc_sec) = exe.section_by_name(".reloc") else {
        anyhow::bail!("Missing .reloc section");
    };

    let exe_data = map_pe_image(exe);
    let mut coff_data = exe_data.clone();
    let mut relocs_rva = BTreeMap::<usize, RelocKind>::new();
    let mut observed_aliases = RelocAliasObservations::default();

    let mut pos = 0;
    let reloc_data = reloc_sec.data()?;
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
                        let Some((owner_function_rva, _)) =
                            symbols.functions.range(..=reloc_rva).next_back()
                        else {
                            anyhow::bail!(
                                "function relocation site {reloc_rva:#x} has no containing function"
                            );
                        };
                        reloc_aliases.resolve_function_alias(
                            *owner_function_rva,
                            target_rva,
                            reloc_rva,
                            function_overloads,
                            &mut observed_aliases,
                        )?
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
                            &symbols.functions,
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
                                    let Some((constant_rva, constant_name)) =
                                        symbols.constants.range(..=target_rva).next_back()
                                    else {
                                        unreachable!("All constants must be named");
                                    };

                                    // @TODO: Many relocations (~2k) have very huge diffs,
                                    // meaning they do not actually belong to a found symbol.
                                    // This needs to be investigated (if this will affect objdiff matching)
                                    let diff = u32::try_from(target_rva - *constant_rva)?;
                                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                                    relocs_rva.insert(
                                        reloc_rva,
                                        RelocKind::Constant {
                                            symbol: *constant_name,
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
                            &symbols.functions,
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
                            let Some((static_rva, static_name)) =
                                symbols.statics.range(..=target_rva).next_back()
                            else {
                                let _reloc_va = reloc_rva + env.image_base.to_usize();
                                // @TODO: There is a "single" unnamed static relocation in base, which is a
                                // string "rb\0" used for `fopen` in `ov_fopen`.
                                continue;
                            };

                            // @TODO: Many relocations (~10k) have very huge diffs,
                            // meaning they do not actually belong to a found symbol.
                            // This needs to be investigated (if this will affect objdiff matching)
                            let diff = u32::try_from(target_rva - *static_rva)?;
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::Static {
                                    symbol: *static_name,
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

    Ok(ResolvedRelocations {
        coff_data,
        by_rva: relocs_rva,
        observed_aliases,
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
