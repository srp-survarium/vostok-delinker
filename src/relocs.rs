use crate::Env;
use crate::data_manifest::DataManifest;
use crate::pdb_symbols;
use crate::reloc_manifest::RelocManifest;
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
    reloc_manifest: Option<&RelocManifest>,
    rediscover_from_pdb: bool,
    rediscovery_interior_bound: usize,
) -> anyhow::Result<(Vec<u8>, BTreeMap<usize, RelocKind<'s>>)> {
    let exe_data = map_pe_image(exe);
    let mut coff_data = exe_data.clone();
    let mut relocs_rva = BTreeMap::<usize, RelocKind>::new();

    // Absolute sites come from the `.reloc` directory, or -- for a stripped image
    // that has none -- from a reviewed reloc manifest and/or PDB rediscovery. A
    // present directory is already complete, so a recovery method alongside it is
    // redundant; recovering nothing would silently drop real relocations.
    let recovery = reloc_manifest.is_some() || rediscover_from_pdb;
    match (exe.section_by_name(".reloc"), recovery) {
        (Some(section), false) => {
            resolve_reloc_directory(
                section.data()?,
                env,
                symbols,
                data_manifest,
                manifest_coverage,
                &exe_data,
                &mut coff_data,
                &mut relocs_rva,
            )?;
        }
        (None, true) => {
            // Manifest sites are authoritative; rediscovery then fills the rest.
            if let Some(reloc_manifest) = reloc_manifest {
                resolve_manifest_sites(
                    reloc_manifest,
                    env,
                    symbols,
                    data_manifest,
                    manifest_coverage,
                    &exe_data,
                    &mut coff_data,
                    &mut relocs_rva,
                )?;
            }
            if rediscover_from_pdb {
                rediscover_absolute_sites_from_pdb(
                    env,
                    symbols,
                    data_manifest,
                    manifest_coverage,
                    &exe_data,
                    &mut coff_data,
                    &mut relocs_rva,
                    rediscovery_interior_bound,
                )?;
            }
        }

        (Some(_), true) => anyhow::bail!(
            "image already has a `.reloc` base-relocation directory; --reloc-manifest \
             and --rediscover-relocations-from-pdb are only for images without one"
        ),
        (None, false) => anyhow::bail!(
            "image has no `.reloc` base-relocation directory; supply --reloc-manifest \
             and/or --rediscover-relocations-from-pdb to recover its absolute relocations"
        ),
    };

    Ok((coff_data, relocs_rva))
}

/// Resolve every HIGHLOW site in the PE base-relocation directory (`.reloc`).
#[allow(clippy::too_many_arguments)]
fn resolve_reloc_directory<'s>(
    reloc_data: &[u8],
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
) -> anyhow::Result<()> {
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
            const RELOC_TYP_HIGHLOW: u16 = 3;
            if entry >> 12 != RELOC_TYP_HIGHLOW {
                continue;
            }
            let reloc_rva = (page_rva + u32::from(entry & 0x0FFF)).to_usize();
            resolve_absolute_site(
                env,
                symbols,
                data_manifest,
                manifest_coverage,
                exe_data,
                coff_data,
                relocs_rva,
                reloc_rva,
            )?;
        }
    }
    Ok(())
}

/// Resolve every reviewed site listed in the reloc manifest.
#[allow(clippy::too_many_arguments)]
fn resolve_manifest_sites<'s>(
    reloc_manifest: &RelocManifest,
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
) -> anyhow::Result<()> {
    for &site in reloc_manifest.sites() {
        if site + 4 > exe_data.len() {
            anyhow::bail!("reloc manifest site RVA {site:#x} is outside the mapped image");
        }
        resolve_absolute_site(
            env,
            symbols,
            data_manifest,
            manifest_coverage,
            exe_data,
            coff_data,
            relocs_rva,
            site,
        )?;
    }
    Ok(())
}

/// Rediscover absolute relocation sites for an image with no (or a partial)
/// `.reloc` directory: scan `.text`/`.rdata`/`.data` for fields holding a known
/// PDB symbol VA and resolve each fresh one. Best-effort; `.reloc` sites are kept.
#[allow(clippy::too_many_arguments)]
fn rediscover_absolute_sites_from_pdb<'s>(
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    interior_bound: usize,
) -> anyhow::Result<()> {
    let image_base = env.image_base.to_usize();
    let mut starts: Vec<usize> = symbols
        .functions
        .keys()
        .chain(symbols.statics.keys())
        .chain(symbols.constants.keys())
        .chain(symbols.strings.keys())
        .copied()
        .collect();
    starts.sort_unstable();
    starts.dedup();

    for (start, size) in [
        (env.text.rva, env.text.size),
        (env.rdata.rva, env.rdata.size),
        (env.data.rva, env.data.size),
    ] {
        let end = (start + size).min(exe_data.len());
        let mut site = start;
        while site + 4 <= end {
            let value = u32::from_le_bytes(exe_data[site..site + 4].try_into().unwrap()) as usize;
            if value >= image_base
                && rediscovered_target_is_known(&starts, value - image_base, interior_bound)
                && !relocs_rva.contains_key(&site)
            {
                resolve_absolute_site(
                    env,
                    symbols,
                    data_manifest,
                    manifest_coverage,
                    exe_data,
                    coff_data,
                    relocs_rva,
                    site,
                )?;
            }
            site += 1;
        }
    }

    Ok(())
}

/// Resolve one absolute relocation site (a field at `reloc_rva` holding a target
/// VA): classify the target, rewrite the field to its in-object addend, and record
/// the `RelocKind`. Shared by every site source (`.reloc`, PDB rediscovery, ...).
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

/// Trust a rediscovered target when it is a known symbol start, or within
/// `interior_bound` bytes after one (an interior pointer). `starts` is sorted.
fn rediscovered_target_is_known(
    starts: &[usize],
    target_rva: usize,
    interior_bound: usize,
) -> bool {
    match starts.binary_search(&target_rva) {
        Ok(_) => true,
        Err(index) => {
            interior_bound > 0 && index > 0 && target_rva - starts[index - 1] < interior_bound
        }
    }
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
    use super::rediscovered_target_is_known;

    #[test]
    fn rediscovered_target_matches_starts_and_interior() {
        let starts = [0x1000usize, 0x2000, 0x2040];
        // Exact symbol starts always match.
        assert!(rediscovered_target_is_known(&starts, 0x1000, 0));
        assert!(rediscovered_target_is_known(&starts, 0x2040, 0));
        // With bound 0, interior addresses are rejected.
        assert!(!rediscovered_target_is_known(&starts, 0x1004, 0));
        // Within `interior_bound` bytes after a start (half-open) is accepted.
        assert!(rediscovered_target_is_known(&starts, 0x1004, 0x20));
        assert!(!rediscovered_target_is_known(&starts, 0x1020, 0x20));
        assert!(rediscovered_target_is_known(&starts, 0x2038, 0x100));
        // Below the first start, and far past the last beyond the bound, never match.
        assert!(!rediscovered_target_is_known(&starts, 0x0800, 0x1000));
        assert!(!rediscovered_target_is_known(&starts, 0x3000, 0x40));
    }
}
