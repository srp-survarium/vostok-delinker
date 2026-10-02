use crate::Env;
use crate::data_manifest::{DataManifest, DataStorage};
use crate::pdb_symbols::{self, FunctionRelocationField, PdbDataSymbol};
use crate::reloc_alias_manifest::{RelocAliasManifest, RelocAliasObservations};
use crate::reloc_manifest::RelocManifest;
use crate::utils::ToUsize;

use pdb2::RawString;

use object::LittleEndian;
use object::{Object, ObjectSection};

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
pub enum RelocKind<'a> {
    // IAT - the target is an import address table slot named by an exact PDB
    // symbol (`__imp__...`). Always emitted as an external reference with a
    // zero addend.
    Import {
        symbol: RawString<'static>,
    },

    // .text - resolved from a PDB function symbol. Always emitted as an external
    // reference to that function.
    Function {
        overloads: &'a [RawString<'static>],
        symbol: Option<RawString<'static>>,
        encoding: RelocationEncoding,
    },

    // Reviewed: the target is a named definition that some object owns: one in
    // the `--data-manifest`, or a PDB data record in `.text`. Always emitted as
    // an external reference to it.
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
        storage: DataStorage,
    },
}

/// Where retail `.data` stops holding initialized bytes; beyond lies the
/// linker's zero-fill (`.bss`) tail.
#[derive(Copy, Clone, Debug)]
pub struct WritableExtent {
    rva: usize,
    initialized_size: usize,
}

impl WritableExtent {
    pub fn of(env: &Env) -> Self {
        Self {
            rva: env.data.rva,
            initialized_size: env.data.data.len(),
        }
    }

    #[cfg(test)]
    pub fn all_initialized() -> Self {
        Self {
            rva: 0,
            initialized_size: usize::MAX,
        }
    }

    /// Storage of a target inside retail `.data`.
    pub fn storage(self, target_rva: usize) -> DataStorage {
        if target_rva - self.rva < self.initialized_size {
            DataStorage::Data
        } else {
            DataStorage::Bss
        }
    }
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

#[derive(Default)]
struct OutOfExtentFallbacks {
    constants: usize,
    statics: usize,
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

    let resolves =
        |owner_rva: usize| (owner_rva as u32).wrapping_add(alias.addend) == target_rva as u32;
    let mut exact = owners
        .iter()
        .filter(|(_, symbol)| symbol.name == alias.owner);
    let (owner_rva, owner) = match (exact.next(), exact.next()) {
        (Some((owner_rva, symbol)), None) => (*owner_rva, symbol.name),
        (Some(_), Some(_)) => anyhow::bail!(
            "relocation alias owner is ambiguous in the PDB: {}",
            alias.owner
        ),
        (None, _) => {
            // A function-local static is `name$S<ordinal>` in CodeView, and the
            // ordinal shifts whenever its function changes. A reviewed row may
            // spell it `name$S`; the live symbol that resolves the row answers.
            let mut statics = owners.iter().filter(|(owner_rva, symbol)| {
                is_ordinal_of_static(symbol.name.as_bytes(), alias.owner.as_bytes())
                    && resolves(**owner_rva)
            });
            match (statics.next(), statics.next()) {
                (Some((owner_rva, symbol)), None) => (*owner_rva, symbol.name),
                (Some(_), Some(_)) => anyhow::bail!(
                    "relocation alias owner is ambiguous in the PDB: {}",
                    alias.owner
                ),
                (None, _) => anyhow::bail!(
                    "relocation alias owner is absent from the PDB: {}",
                    alias.owner
                ),
            }
        }
    };
    if !resolves(owner_rva) {
        anyhow::bail!("relocation alias owner/addend does not resolve to target");
    }

    Ok(Some((alias.addend, owner)))
}

/// Whether `live` is `spelling` (which ends in `$S`) plus a CodeView ordinal.
fn is_ordinal_of_static(live: &[u8], spelling: &[u8]) -> bool {
    spelling.ends_with(b"$S")
        && live
            .strip_prefix(spelling)
            .is_some_and(|ordinal| !ordinal.is_empty() && ordinal.iter().all(u8::is_ascii_digit))
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
    writable: WritableExtent,
    owner_function_rva: usize,
    reloc_rva: usize,
    target_rva: usize,
) -> anyhow::Result<Option<(RelocKind<'s>, u32)>> {
    if let Some(symbol) = symbols.data_outside_functions(target_rva) {
        return Ok(Some((RelocKind::ReviewedData { symbol }, 0)));
    }
    let target_rva = symbols.resolve_incremental_trampoline(target_rva);
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

    let (owners, storage) = match exact {
        ExactPdbDataTarget::ConstantString { .. } | ExactPdbDataTarget::Constant { .. } => {
            (&symbols.constants, DataStorage::Rdata)
        }
        ExactPdbDataTarget::Static { .. } => (&symbols.statics, writable.storage(target_rva)),
    };
    if let Some((addend, owner)) = resolve_manifest_alias(
        reloc_aliases,
        owners,
        symbols,
        observed_aliases,
        reloc_rva,
        target_rva,
    )? {
        let kind = if storage != DataStorage::Rdata {
            RelocKind::ConjuredStatic {
                symbol: owner,
                target_rva,
                storage,
            }
        } else {
            RelocKind::ConjuredConstant {
                symbol: owner,
                target_rva,
            }
        };
        let owner_rva = (target_rva as u32).wrapping_sub(addend) as usize;
        return Ok(Some((
            referenced_if_defined(data_manifest, owner_rva, kind),
            addend,
        )));
    }

    if let Some((owner, addend)) = data_manifest
        .owner_and_addend_for_rva(target_rva)
        .or_else(|| data_manifest.provisional_owner_and_addend_for_rva(target_rva, storage))
    {
        let addend = u32::try_from(addend)?;
        return Ok(Some((
            RelocKind::ReviewedData {
                symbol: owner.symbol_name,
            },
            addend,
        )));
    }

    if manifest_coverage == ManifestCoverage::RequireComplete {
        anyhow::bail!(
            "--strict: recovered instruction relocation at RVA {reloc_rva:#x} targets data RVA {target_rva:#x}, which is not covered by the data manifest"
        );
    }

    if let ExactPdbDataTarget::Constant { symbol } | ExactPdbDataTarget::Static { symbol } = exact {
        refuse_unprovisioned(symbol, reloc_rva, target_rva)?;
    }
    let kind = match exact {
        ExactPdbDataTarget::ConstantString { symbol, data } => {
            RelocKind::ConjuredString { symbol, data }
        }
        ExactPdbDataTarget::Constant { symbol } => {
            RelocKind::ConjuredConstant { symbol, target_rva }
        }
        ExactPdbDataTarget::Static { symbol } => RelocKind::ConjuredStatic {
            symbol,
            target_rva,
            storage,
        },
    };
    Ok(Some((
        referenced_if_defined(data_manifest, target_rva, kind),
        0,
    )))
}

/// A PDB synthesizer can place a fence symbol named `UNPROVISIONED_...` at a
/// relocation target it knows the original identity of but cannot yet spell,
/// so that nearest-symbol recovery cannot misattribute the address to a
/// neighbour. Emitting the fence would invent an identity; fail instead.
const UNPROVISIONED_PREFIX: &[u8] = b"UNPROVISIONED_";

fn refuse_unprovisioned(
    symbol: RawString<'_>,
    reloc_rva: usize,
    target_rva: usize,
) -> anyhow::Result<()> {
    if symbol.as_bytes().starts_with(UNPROVISIONED_PREFIX) {
        anyhow::bail!(
            "relocation at RVA {reloc_rva:#x} targets data RVA {target_rva:#x}, which resolves \
             only to the fence {symbol}; provide its identity in the data manifest or the \
             relocation alias manifest"
        );
    }
    Ok(())
}

/// A conjured target spelled with the name of a data manifest definition refers
/// to that definition, in whichever object owns it, instead of becoming a
/// private copy in the referencing object. The definition must be the PDB
/// symbol's own (it starts at `symbol_rva`) or external: a local of the same
/// name elsewhere is another variable.
fn referenced_if_defined<'s>(
    data_manifest: &DataManifest,
    symbol_rva: usize,
    kind: RelocKind<'s>,
) -> RelocKind<'s> {
    match kind {
        RelocKind::ConjuredConstant { symbol, .. } | RelocKind::ConjuredStatic { symbol, .. }
            if data_manifest.defines(symbol.as_bytes(), symbol_rva) =>
        {
            RelocKind::ReviewedData { symbol }
        }
        kind => kind,
    }
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
    reloc_manifest: Option<&RelocManifest>,
    rediscover_from_pdb: bool,
    rediscovery_interior_bound: usize,
) -> anyhow::Result<ResolvedRelocations<'s>> {
    let (source, reloc_data) = base_relocation_data(exe)?;

    let exe_data = map_pe_image(exe);
    let mut coff_data = exe_data.clone();
    let mut relocs_rva = BTreeMap::<usize, RelocKind>::new();
    let mut observed_aliases = RelocAliasObservations::default();
    let mut out_of_extent = OutOfExtentFallbacks::default();

    // Absolute sites come from the base-relocation directory, or -- for an image
    // that has none -- from a reviewed reloc manifest and/or PDB rediscovery. A
    // present directory is already complete, so a recovery method alongside it is
    // redundant; recovering nothing would silently drop real relocations.
    let recovery = reloc_manifest.is_some() || rediscover_from_pdb;
    match (source, recovery) {
        (BaseRelocationSource::Directory { .. }, false) => {
            resolve_reloc_directory(
                reloc_data,
                env,
                symbols,
                data_manifest,
                reloc_aliases,
                manifest_coverage,
                &exe_data,
                &mut coff_data,
                &mut relocs_rva,
                &mut observed_aliases,
                &mut out_of_extent,
            )?;
        }
        (BaseRelocationSource::Stripped | BaseRelocationSource::Absent, true) => {
            // Manifest sites are authoritative; rediscovery then fills the rest.
            if let Some(reloc_manifest) = reloc_manifest {
                resolve_manifest_sites(
                    reloc_manifest,
                    env,
                    symbols,
                    data_manifest,
                    reloc_aliases,
                    manifest_coverage,
                    &exe_data,
                    &mut coff_data,
                    &mut relocs_rva,
                    &mut observed_aliases,
                    &mut out_of_extent,
                )?;
            }
            if rediscover_from_pdb {
                rediscover_absolute_sites_from_pdb(
                    env,
                    symbols,
                    data_manifest,
                    reloc_aliases,
                    manifest_coverage,
                    &exe_data,
                    &mut coff_data,
                    &mut relocs_rva,
                    &mut observed_aliases,
                    &mut out_of_extent,
                    rediscovery_interior_bound,
                )?;
            }
        }

        (BaseRelocationSource::Directory { .. }, true) => anyhow::bail!(
            "image already has a PE base-relocation directory; --reloc-manifest \
             and --rediscover-relocations-from-pdb are only for images without one"
        ),
        (BaseRelocationSource::Stripped | BaseRelocationSource::Absent, false) => anyhow::bail!(
            "image has no PE base-relocation directory; supply --reloc-manifest \
             and/or --rediscover-relocations-from-pdb to recover its absolute relocations"
        ),
    };

    if out_of_extent.constants != 0 || out_of_extent.statics != 0 {
        eprintln!(
            "[relocs] {} .rdata and {} .data relocations fall back to a PDB symbol whose type size does not reach their target",
            out_of_extent.constants, out_of_extent.statics
        );
    }

    Ok(ResolvedRelocations {
        coff_data,
        by_rva: relocs_rva,
        observed_aliases,
        source,
    })
}

/// Resolve every HIGHLOW site in the PE base-relocation directory (`.reloc`).
#[allow(clippy::too_many_arguments)]
fn resolve_reloc_directory<'s>(
    reloc_data: &[u8],
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    observed_aliases: &mut RelocAliasObservations,
    out_of_extent: &mut OutOfExtentFallbacks,
) -> anyhow::Result<()> {
    for reloc_rva in highlow_sites(reloc_data)? {
        resolve_absolute_site(
            env,
            symbols,
            data_manifest,
            reloc_aliases,
            manifest_coverage,
            exe_data,
            coff_data,
            relocs_rva,
            observed_aliases,
            out_of_extent,
            reloc_rva,
        )?;
    }
    Ok(())
}

/// The RVA of every HIGHLOW entry in a base-relocation directory.
fn highlow_sites(reloc_data: &[u8]) -> anyhow::Result<Vec<usize>> {
    const RELOC_TYP_HIGHLOW: u16 = 3;
    let mut sites = Vec::new();
    let mut pos = 0;
    while pos + HEADER_SIZE <= reloc_data.len() {
        let RelocHeader {
            page_rva,
            block_size,
        } = bytemuck::pod_read_unaligned::<RelocHeader>(&reloc_data[pos..pos + HEADER_SIZE]);
        if block_size < 8 {
            break;
        }
        let block_end = pos + block_size.to_usize();
        if block_end > reloc_data.len() {
            anyhow::bail!("base relocation block at offset {pos:#x} is truncated");
        }
        let entries: &[RelocEntry] =
            bytemuck::cast_slice(&reloc_data[pos + HEADER_SIZE..block_end]);
        pos = block_end;
        sites.extend(
            entries
                .iter()
                .filter(|RelocEntry { entry }| entry >> 12 == RELOC_TYP_HIGHLOW)
                .map(|RelocEntry { entry }| (page_rva + u32::from(entry & 0x0FFF)).to_usize()),
        );
    }
    Ok(sites)
}

/// The HIGHLOW sites of the image's base-relocation directory, if it has one.
pub(crate) fn retained_highlow_sites(
    exe: &'static object::read::pe::PeFile32<'static>,
) -> anyhow::Result<Option<Vec<usize>>> {
    match base_relocation_data(exe)? {
        (BaseRelocationSource::Directory { .. }, data) => highlow_sites(data).map(Some),
        (BaseRelocationSource::Stripped | BaseRelocationSource::Absent, _) => Ok(None),
    }
}

/// Resolve every reviewed site listed in the reloc manifest.
#[allow(clippy::too_many_arguments)]
fn resolve_manifest_sites<'s>(
    reloc_manifest: &RelocManifest,
    env: &Env,
    symbols: &'s pdb_symbols::PdbSymbols,
    data_manifest: &DataManifest,
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    observed_aliases: &mut RelocAliasObservations,
    out_of_extent: &mut OutOfExtentFallbacks,
) -> anyhow::Result<()> {
    for &site in reloc_manifest.sites() {
        if site + 4 > exe_data.len() {
            anyhow::bail!("reloc manifest site RVA {site:#x} is outside the mapped image");
        }
        resolve_absolute_site(
            env,
            symbols,
            data_manifest,
            reloc_aliases,
            manifest_coverage,
            exe_data,
            coff_data,
            relocs_rva,
            observed_aliases,
            out_of_extent,
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
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    observed_aliases: &mut RelocAliasObservations,
    out_of_extent: &mut OutOfExtentFallbacks,
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
                    reloc_aliases,
                    manifest_coverage,
                    exe_data,
                    coff_data,
                    relocs_rva,
                    observed_aliases,
                    out_of_extent,
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
    reloc_aliases: &RelocAliasManifest,
    manifest_coverage: ManifestCoverage,
    exe_data: &[u8],
    coff_data: &mut [u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
    observed_aliases: &mut RelocAliasObservations,
    out_of_extent: &mut OutOfExtentFallbacks,
    reloc_rva: usize,
) -> anyhow::Result<()> {
    let target_va = bytemuck::pod_read_unaligned::<u32>(&exe_data[reloc_rva..reloc_rva + 4]);
    let linked_target_rva = (target_va - env.image_base).to_usize();
    let target_rva = symbols.resolve_incremental_trampoline(linked_target_rva);

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
        // An explicit data record in code outranks the function before it.
        // Only its exact start is known: an untyped record has no extent.
        () if let Some(symbol) = symbols.data_outside_functions(linked_target_rva) => {
            coff_data_reloc.copy_from_slice(&0_u32.to_le_bytes());
            relocs_rva.insert(reloc_rva, RelocKind::ReviewedData { symbol });
        }
        () if (env.text.rva..env.text.rva + env.text.size).contains(&target_rva) => {
            let (function_rva, function_overloads) = symbols
                .functions
                .range(..=target_rva)
                .next_back()
                .expect("all function relocs to be named");

            let diff = u32::try_from(target_rva - *function_rva)?;
            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

            let symbol =
                if diff == 0 && (env.text.rva..env.text.rva + env.text.size).contains(&reloc_rva) {
                    match symbols.relocation_field_owner(reloc_rva) {
                        FunctionRelocationField::Within { function_rva } => reloc_aliases
                            .resolve_function_alias(
                                function_rva,
                                target_rva,
                                reloc_rva,
                                function_overloads,
                                observed_aliases,
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
                    observed_aliases,
                    reloc_rva,
                    target_rva,
                )?
            {
                coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                relocs_rva.insert(
                    reloc_rva,
                    referenced_if_defined(
                        data_manifest,
                        (target_rva as u32).wrapping_sub(addend) as usize,
                        RelocKind::ConjuredConstant {
                            symbol: owner,
                            target_rva,
                        },
                    ),
                );
                return Ok(());
            }
            let owner = data_manifest
                .owner_and_addend_for_rva(target_rva)
                .or_else(|| {
                    data_manifest
                        .provisional_owner_and_addend_for_rva(target_rva, DataStorage::Rdata)
                });
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
                            let Some((constant_rva, constant)) =
                                symbols.constants.range(..=target_rva).next_back()
                            else {
                                unreachable!("All constants must be named");
                            };

                            if !constant.contains(*constant_rva, target_rva) {
                                out_of_extent.constants += 1;
                            }
                            refuse_unprovisioned(constant.name, reloc_rva, target_rva)?;
                            let diff = u32::try_from(target_rva - *constant_rva)?;
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                            relocs_rva.insert(
                                reloc_rva,
                                referenced_if_defined(
                                    data_manifest,
                                    *constant_rva,
                                    RelocKind::ConjuredConstant {
                                        symbol: constant.name,
                                        target_rva,
                                    },
                                ),
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
                    observed_aliases,
                    reloc_rva,
                    target_rva,
                )?
            {
                coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                relocs_rva.insert(
                    reloc_rva,
                    referenced_if_defined(
                        data_manifest,
                        (target_rva as u32).wrapping_sub(addend) as usize,
                        RelocKind::ConjuredStatic {
                            symbol: owner,
                            target_rva,
                            // The owner's storage, which an end-of-array target
                            // past its extent need not share.
                            storage: WritableExtent::of(env)
                                .storage((target_rva as u32).wrapping_sub(addend) as usize),
                        },
                    ),
                );
                return Ok(());
            }
            let owner = data_manifest
                .owner_and_addend_for_rva(target_rva)
                .or_else(|| {
                    data_manifest.provisional_owner_and_addend_for_rva(
                        target_rva,
                        WritableExtent::of(env).storage(target_rva),
                    )
                });
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
                    let Some((static_rva, static_symbol)) =
                        symbols.statics.range(..=target_rva).next_back()
                    else {
                        let _reloc_va = reloc_rva + env.image_base.to_usize();
                        // @TODO: There is a "single" unnamed static relocation in base, which is a
                        // string "rb\0" used for `fopen` in `ov_fopen`.
                        return Ok(());
                    };

                    if !static_symbol.contains(*static_rva, target_rva) {
                        out_of_extent.statics += 1;
                    }
                    refuse_unprovisioned(static_symbol.name, reloc_rva, target_rva)?;
                    let diff = u32::try_from(target_rva - *static_rva)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                    relocs_rva.insert(
                        reloc_rva,
                        referenced_if_defined(
                            data_manifest,
                            *static_rva,
                            RelocKind::ConjuredStatic {
                                symbol: static_symbol.name,
                                target_rva,
                                storage: WritableExtent::of(env).storage(target_rva),
                            },
                        ),
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
    use super::*;

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
            .add_incremental_trampoline_at_rva(0x1800, 0x2000, 5)
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
            WritableExtent::all_initialized(),
            0x1000,
            0x1010,
            0x2000,
        )
        .unwrap();
        assert!(matches!(function, Some((RelocKind::Function { .. }, 0))));
        let trampoline = classify_exact_pdb_target(
            &symbols,
            &manifest,
            &aliases,
            &mut observed,
            ManifestCoverage::AllowPartial,
            WritableExtent::all_initialized(),
            0x1000,
            0x1012,
            0x1800,
        )
        .unwrap();
        assert!(matches!(
            trampoline,
            Some((RelocKind::Function { overloads, .. }, 0))
                if overloads[0].as_bytes() == b"exact"
        ));
        let import = classify_exact_pdb_target(
            &symbols,
            &manifest,
            &aliases,
            &mut observed,
            ManifestCoverage::AllowPartial,
            WritableExtent::all_initialized(),
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
                WritableExtent::all_initialized(),
                0x1000,
                0x1018,
                0x2001,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn ordinal_free_static_spelling_selects_the_live_symbol_that_resolves() {
        let mut symbols = pdb_symbols::PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"function"[..]), Some(0x40))
            .unwrap();
        for (rva, name) in [
            (0x4000, &b"_s_mask$S12"[..]),
            (0x4100, &b"_s_mask$S7"[..]),
            (0x4200, &b"_s_mask$Sx"[..]),
        ] {
            symbols
                .statics
                .insert(rva, PdbDataSymbol::new(RawString::from(name), None));
        }
        let aliases = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences\n\
              0x1000\t0x40f2\t0x1010\t_s_mask$S\t0xfffffff2\t1\n\
              0x1000\t0x4200\t0x1020\t_s_mask$S\t0\t1\n",
            std::path::Path::new("aliases.tsv"),
        )
        .unwrap();
        let mut observed = RelocAliasObservations::default();

        let (addend, owner) = resolve_manifest_alias(
            &aliases,
            &symbols.statics,
            &symbols,
            &mut observed,
            0x1010,
            0x40f2,
        )
        .unwrap()
        .unwrap();
        assert_eq!((addend, owner.as_bytes()), (0xfffffff2, &b"_s_mask$S7"[..]));

        let error = resolve_manifest_alias(
            &aliases,
            &symbols.statics,
            &symbols,
            &mut observed,
            0x1020,
            0x4200,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("absent"), "{error}");
    }

    #[test]
    fn data_record_in_code_outranks_the_function_before_it() {
        let mut symbols = pdb_symbols::PdbSymbols::default();
        symbols
            .add_function_at_rva(0x1000, RawString::from(&b"owner"[..]), Some(0x20))
            .unwrap();
        symbols
            .text_data
            .insert(0x1020, RawString::from(&b"_s_table"[..]));
        // A switch table inside the function stays part of its code.
        symbols
            .text_data
            .insert(0x1010, RawString::from(&b"const_00401010"[..]));
        let classify = |target_rva| {
            classify_exact_pdb_target(
                &symbols,
                &DataManifest::default(),
                &RelocAliasManifest::default(),
                &mut RelocAliasObservations::default(),
                ManifestCoverage::RequireComplete,
                WritableExtent::all_initialized(),
                0x1000,
                0x1010,
                target_rva,
            )
            .unwrap()
        };
        assert!(matches!(
            classify(0x1020),
            Some((RelocKind::ReviewedData { symbol }, 0)) if symbol.as_bytes() == b"_s_table"
        ));
        assert!(classify(0x1024).is_none());
        assert!(classify(0x1010).is_none());
        assert!(symbols.data_outside_functions(0x1010).is_none());
    }

    #[test]
    fn unprovisioned_fences_are_refused_and_other_names_pass() {
        let error = refuse_unprovisioned(
            RawString::from(&b"UNPROVISIONED_00653c34"[..]),
            0x1010,
            0x253c34,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("0x1010") && error.contains("0x253c34"),
            "{error}"
        );
        assert!(error.contains("UNPROVISIONED_00653c34"), "{error}");
        for name in [&b"DAT_005f0af0"[..], b"?g_cmdBitTable@@3PBGB"] {
            assert!(refuse_unprovisioned(RawString::from(name), 0x1010, 0x1f0af0).is_ok());
        }

        let mut symbols = pdb_symbols::PdbSymbols::default();
        symbols.statics.insert(
            0x4000,
            PdbDataSymbol::new(RawString::from(&b"UNPROVISIONED_00404000"[..]), None),
        );
        let error = classify_exact_pdb_target(
            &symbols,
            &DataManifest::default(),
            &RelocAliasManifest::default(),
            &mut RelocAliasObservations::default(),
            ManifestCoverage::AllowPartial,
            WritableExtent::all_initialized(),
            0x1000,
            0x1010,
            0x4000,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("fence"), "{error}");
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
            WritableExtent::all_initialized(),
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
    fn highlow_sites_walk_every_block_and_reject_truncation() {
        let block = |page: u32, entries: &[u16]| {
            let mut bytes = page.to_le_bytes().to_vec();
            bytes.extend_from_slice(&(8 + 2 * entries.len() as u32).to_le_bytes());
            for entry in entries {
                bytes.extend_from_slice(&entry.to_le_bytes());
            }
            bytes
        };
        // HIGHLOW entries at 0x1004 and 0x2ff8; an ABSOLUTE padding entry is skipped.
        let mut directory = block(0x1000, &[0x3004, 0x0000]);
        directory.extend(block(0x2000, &[0x3ff8, 0x0000]));
        assert_eq!(highlow_sites(&directory).unwrap(), [0x1004, 0x2ff8]);

        let mut truncated = block(0x1000, &[0x3004, 0x0000]);
        truncated[4] = 0x20;
        let error = highlow_sites(&truncated).unwrap_err().to_string();
        assert!(error.contains("truncated"), "{error}");
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
