use crate::Env;
use crate::data_manifest::DataManifest;
use crate::pdb_symbols;
use crate::utils::ToUsize;

use pdb2::RawString;

use object::LittleEndian;
use object::{Object, ObjectSection};

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
pub enum RelocKind<'a> {
    // .text - resolved from a PDB function symbol. Always emitted as an external
    // reference to that function.
    Function {
        overloads: &'a [RawString<'static>],
        encoding: RelocationEncoding,
    },

    // Reviewed: the target is a definition in the `--data-manifest`. Always
    // emitted as an external reference to that shared definition, which its
    // owning object defines. Covers both `.rdata` and `.data` targets.
    ReviewedData {
        symbol: RawString<'static>,
    },

    // Conjured: the target is NOT covered by the manifest, so it is reconstructed
    // algorithmically from a PDB symbol and materialized as a private per-TU copy
    // (unless only a reference is wanted). One variant per source section.
    ConjuredString {
        symbol: RawString<'static>,
        data: &'a [u8],
    },
    ConjuredConstant {
        symbol: RawString<'static>,
        target_rva: usize,
    },
    ConjuredStatic {
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
    manifest_coverage: ManifestCoverage,
) -> anyhow::Result<(Vec<u8>, BTreeMap<usize, RelocKind<'s>>)> {
    let Some(reloc_sec) = exe.section_by_name(".reloc") else {
        anyhow::bail!("Missing .reloc section");
    };

    let exe_data = map_pe_image(exe);
    let mut coff_data = exe_data.clone();
    let mut relocs_rva = BTreeMap::<usize, RelocKind>::new();

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

            resolve_absolute_site(
                env,
                symbols,
                data_manifest,
                manifest_coverage,
                &exe_data,
                &mut coff_data,
                &mut relocs_rva,
                reloc_rva,
            )?;
        }
    }

    Ok((coff_data, relocs_rva))
}

/// Resolve one absolute relocation site: a 4-byte field at `reloc_rva` holding a
/// linked target VA. Classify the target against the PDB symbols and the data
/// manifest, rewrite the field in `coff_data` to the in-object addend, and record
/// the `RelocKind`. This is the per-site body shared by every site source (the
/// `.reloc` directory today; PDB rediscovery and the reloc manifest later).
fn resolve_absolute_site<'s>(
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    reloc_rva: usize,
) -> anyhow::Result<()> {
    let target_va = bytemuck::pod_read_unaligned::<u32>(&exe_data[reloc_rva..reloc_rva + 4]);
    let target_rva = (target_va - env.image_base).to_usize();

    let coff_data_reloc = &mut coff_data[reloc_rva..reloc_rva + 4];

    match () {
        () if (env.text.rva..env.text.rva + env.text.size).contains(&target_rva) => {
            let (function_rva, function_overloads) = symbols
                .functions
                .range(..=target_rva)
                .next_back()
                .expect("all function relocs to be named");

            let diff = u32::try_from(target_rva - *function_rva)?;
            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

            relocs_rva.insert(
                reloc_rva,
                RelocKind::Function {
                    overloads: function_overloads,
                    encoding: RelocationEncoding::Absolute,
                },
            );
        }
        () if (env.rdata.rva..env.rdata.rva + env.rdata.size).contains(&target_rva) => {
            let owner = data_manifest.owner_and_addend_for_rva(target_rva);
            match (manifest_coverage, owner) {
                (_, Some((owner, addend))) => {
                    let diff = u32::try_from(addend)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::ReviewedData {
                            symbol: owner.symbol_name,
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
                                RelocKind::ConjuredString {
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
                                RelocKind::ConjuredConstant {
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
            let owner = data_manifest.owner_and_addend_for_rva(target_rva);
            match (manifest_coverage, owner) {
                (_, Some((owner, addend))) => {
                    let diff = u32::try_from(addend)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::ReviewedData {
                            symbol: owner.symbol_name,
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
                        return Ok(());
                    };

                    // @TODO: Many relocations (~10k) have very huge diffs,
                    // meaning they do not actually belong to a found symbol.
                    // This needs to be investigated (if this will affect objdiff matching)
                    let diff = u32::try_from(target_rva - *static_rva)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::ConjuredStatic {
                            symbol: *static_name,
                            target_rva,
                        },
                    );
                }
            }
        }
        () => (),
    }

    Ok(())
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
