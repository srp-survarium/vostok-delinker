use crate::Env;
use crate::contribution_manifest::{ContributionManifest, ContributionStorage};
use crate::data_manifest::{DataManifest, DataStorage};
use crate::pdb_symbols;
use crate::utils::ToUsize;

use pdb2::RawString;

use object::LittleEndian;
use object::{Object, ObjectSection};

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
pub enum RelocKind<'a> {
    // .text
    Function {
        overloads: &'a [RawString<'static>],
        // True for a PC-relative branch (call/jmp/jcc rel32 -> IMAGE_REL_I386_REL32),
        // false for an absolute code reference taken from the .reloc table
        // (e.g. `push offset fn`, a vftable slot -> IMAGE_REL_I386_DIR32).
        relative: bool,
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
        storage: ContributionStorage,
    },
}

#[repr(C)]
#[derive(bytemuck::AnyBitPattern, bytemuck::NoUninit, Copy, Clone)]
struct RelocHeader {
    page_rva: u32,
    block_size: u32,
}
const HEADER_SIZE: usize = std::mem::size_of::<RelocHeader>();

const DATA_ALIAS_PREFIX: &[u8] = b"__homm2_data_alias$";

fn decode_data_alias(
    symbol: RawString<'static>,
) -> anyhow::Result<Option<(u32, RawString<'static>)>> {
    let bytes = symbol.as_bytes();
    if !bytes.starts_with(DATA_ALIAS_PREFIX) {
        return Ok(None);
    }
    let value_start = DATA_ALIAS_PREFIX.len();
    let value_end = value_start + 8;
    if bytes.len() <= value_end || bytes[value_end] != b'$' {
        anyhow::bail!("malformed canonical data alias: {symbol}");
    }
    let mut addend = 0u32;
    for byte in &bytes[value_start..value_end] {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a' + 10),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => anyhow::bail!("malformed canonical data alias addend: {symbol}"),
        };
        addend = (addend << 4) | digit;
    }
    let owner = &bytes[value_end + 1..];
    if owner.is_empty() {
        anyhow::bail!("canonical data alias has no owner: {symbol}");
    }
    Ok(Some((addend, owner.into())))
}

fn resolve_data_alias(
    symbols: &BTreeMap<usize, RawString<'static>>,
    alias_rva: usize,
    target_rva: usize,
    alias: RawString<'static>,
    storage: ContributionStorage,
    contributions: &ContributionManifest,
) -> anyhow::Result<Option<(u32, RawString<'static>)>> {
    let Some((addend, owner)) = decode_data_alias(alias)? else {
        return Ok(None);
    };
    if alias_rva != target_rva {
        anyhow::bail!("canonical data alias is not at its exact target RVA");
    }
    let Some((owner_rva, _)) = symbols.iter().find(|(_, name)| **name == owner) else {
        anyhow::bail!("canonical data alias owner is absent: {owner}");
    };
    if !contributions.same_owner(storage, *owner_rva, target_rva) {
        anyhow::bail!("canonical data alias crosses compiland contributions");
    }
    if (*owner_rva as u32).wrapping_add(addend) != target_rva as u32 {
        anyhow::bail!("canonical data alias owner/addend does not resolve to target");
    }
    Ok(Some((addend, owner)))
}

fn closest_data_symbol<'a>(
    symbols: &'a BTreeMap<usize, RawString<'static>>,
    target_rva: usize,
    storage: ContributionStorage,
    contributions: &ContributionManifest,
) -> Option<(&'a usize, &'a RawString<'static>)> {
    symbols.range(..=target_rva).rev().find(|(rva, name)| {
        (**rva == target_rva || !name.as_bytes().starts_with(DATA_ALIAS_PREFIX))
            && contributions.same_owner(storage, **rva, target_rva)
    })
}

fn classify_retail_storage(
    rdata_rva: usize,
    rdata_size: usize,
    data_rva: usize,
    data_size: usize,
    data_raw_size: usize,
    target_rva: usize,
) -> Option<ContributionStorage> {
    if (rdata_rva..rdata_rva + rdata_size).contains(&target_rva) {
        Some(ContributionStorage::Rdata)
    } else if (data_rva..data_rva + data_size).contains(&target_rva) {
        Some(if target_rva - data_rva < data_raw_size {
            ContributionStorage::Data
        } else {
            ContributionStorage::Bss
        })
    } else {
        None
    }
}

fn retail_storage_for_rva(env: &Env, target_rva: usize) -> Option<ContributionStorage> {
    classify_retail_storage(
        env.rdata.rva,
        env.rdata.size,
        env.data.rva,
        env.data.size,
        env.data.data.len(),
        target_rva,
    )
}

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
    contributions: &ContributionManifest,
    unresolved: &ContributionManifest,
    recover_data_relocs_from_pdb: bool,
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

            let target_va =
                bytemuck::pod_read_unaligned::<u32>(&exe_data[reloc_rva..reloc_rva + 4]);
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
                            // .reloc HIGHLOW entry -> absolute code reference.
                            relative: false,
                        },
                    );
                }
                () if (env.rdata.rva..env.rdata.rva + env.rdata.size).contains(&target_rva) => {
                    if let Some((owner, addend)) =
                        data_manifest.owner_and_addend_for_rva(target_rva)
                    {
                        let diff = u32::try_from(addend)?;
                        coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Constant {
                                symbol: owner.name,
                                target_rva,
                            },
                        );
                        continue;
                    }
                    let object =
                        contributions.owner_for_rva(ContributionStorage::Rdata, target_rva);
                    if let Some((owner, addend)) = data_manifest
                        .hypothesis_owner_and_addend_for_rva(
                            target_rva,
                            Some(DataStorage::Rdata),
                            object,
                        )
                    {
                        coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Constant {
                                symbol: owner.name,
                                target_rva,
                            },
                        );
                        continue;
                    }
                    if !recover_data_relocs_from_pdb {
                        anyhow::bail!(
                            "no candidate .rdata identity can represent retail RVA {target_rva:#x}"
                        );
                    }
                    match symbols
                        .strings
                        .range(..=target_rva)
                        .rev()
                        .find(|(string_rva, _)| {
                            contributions.same_owner(
                                ContributionStorage::Rdata,
                                **string_rva,
                                target_rva,
                            )
                        }) {
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
                            let Some((constant_rva, constant_name)) = closest_data_symbol(
                                &symbols.constants,
                                target_rva,
                                ContributionStorage::Rdata,
                                contributions,
                            ) else {
                                anyhow::bail!(
                                    "no .rdata symbol in contribution owning RVA {target_rva:#x}"
                                );
                            };

                            let (diff, reloc_name) = match resolve_data_alias(
                                &symbols.constants,
                                *constant_rva,
                                target_rva,
                                *constant_name,
                                ContributionStorage::Rdata,
                                contributions,
                            )? {
                                Some((addend, owner)) => (addend, owner),
                                None => {
                                    (u32::try_from(target_rva - *constant_rva)?, *constant_name)
                                }
                            };
                            coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::Constant {
                                    symbol: reloc_name,
                                    target_rva,
                                },
                            );
                        }
                    };
                }
                () if (env.data.rva..env.data.rva + env.data.size).contains(&target_rva) => {
                    if let Some((owner, addend)) =
                        data_manifest.owner_and_addend_for_rva(target_rva)
                    {
                        let storage = match owner.storage {
                            DataStorage::Bss => ContributionStorage::Bss,
                            DataStorage::Data => ContributionStorage::Data,
                            DataStorage::Rdata => {
                                anyhow::bail!(".rdata manifest owner lies in writable PE storage")
                            }
                        };
                        let diff = u32::try_from(addend)?;
                        coff_data_reloc.copy_from_slice(&diff.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Static {
                                symbol: owner.name,
                                target_rva,
                                storage,
                            },
                        );
                        continue;
                    }
                    let storage = contributions
                        .storage_for_rva(target_rva)
                        .or_else(|| unresolved.storage_for_rva(target_rva))
                        .filter(|storage| {
                            matches!(
                                storage,
                                ContributionStorage::Data | ContributionStorage::Bss
                            )
                        })
                        .or_else(|| retail_storage_for_rva(env, target_rva))
                        .filter(|storage| {
                            matches!(
                                storage,
                                ContributionStorage::Data | ContributionStorage::Bss
                            )
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "writable relocation target {target_rva:#x} has no storage class"
                            )
                        })?;
                    let manifest_storage = match storage {
                        ContributionStorage::Data => DataStorage::Data,
                        ContributionStorage::Bss => DataStorage::Bss,
                        _ => unreachable!(),
                    };
                    let object = contributions.owner_for_rva(storage, target_rva);
                    if let Some((owner, addend)) = data_manifest
                        .hypothesis_owner_and_addend_for_rva(
                            target_rva,
                            Some(manifest_storage),
                            object,
                        )
                    {
                        coff_data_reloc.copy_from_slice(&addend.to_le_bytes());
                        relocs_rva.insert(
                            reloc_rva,
                            RelocKind::Static {
                                symbol: owner.name,
                                target_rva,
                                storage,
                            },
                        );
                        continue;
                    }
                    if !recover_data_relocs_from_pdb {
                        anyhow::bail!(
                            "no candidate writable identity can represent retail RVA {target_rva:#x}"
                        );
                    }
                    let Some((static_rva, static_name)) =
                        closest_data_symbol(&symbols.statics, target_rva, storage, contributions)
                    else {
                        let _reloc_va = reloc_rva + env.image_base.to_usize();
                        // @TODO: There is a "single" unnamed static relocation in base, which is a
                        // string "rb\0" used for `fopen` in `ov_fopen`.
                        continue;
                    };

                    let (diff, reloc_name) = match resolve_data_alias(
                        &symbols.statics,
                        *static_rva,
                        target_rva,
                        *static_name,
                        storage,
                        contributions,
                    )? {
                        Some((addend, owner)) => (addend, owner),
                        None => (u32::try_from(target_rva - *static_rva)?, *static_name),
                    };
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::Static {
                            symbol: reloc_name,
                            target_rva,
                            storage,
                        },
                    );
                }
                () => (),
            }
        }
    }

    Ok((coff_data, relocs_rva))
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
    fn retail_storage_distinguishes_readonly_initialized_and_zero_fill() {
        let classify = |rva| classify_retail_storage(0x100, 0x20, 0x200, 0x40, 0x18, rva);
        assert_eq!(classify(0x110), Some(ContributionStorage::Rdata));
        assert_eq!(classify(0x217), Some(ContributionStorage::Data));
        assert_eq!(classify(0x218), Some(ContributionStorage::Bss));
        assert_eq!(classify(0x240), None);
    }

    #[test]
    fn canonical_alias_decodes_and_validates() {
        let owner: RawString<'static> = b"?gConfig@@3UconfigStruct@@A".as_slice().into();
        let alias: RawString<'static> = b"__homm2_data_alias$00000030$?gConfig@@3UconfigStruct@@A"
            .as_slice()
            .into();
        let mut symbols = BTreeMap::new();
        symbols.insert(0x128d20, owner);
        symbols.insert(0x128d50, alias);
        let contributions = ContributionManifest::default();

        assert_eq!(
            resolve_data_alias(
                &symbols,
                0x128d50,
                0x128d50,
                alias,
                ContributionStorage::Data,
                &contributions,
            )
            .unwrap(),
            Some((0x30, owner))
        );
    }

    #[test]
    fn canonical_alias_rejects_wrong_addend() {
        let owner: RawString<'static> = b"?gConfig@@3UconfigStruct@@A".as_slice().into();
        let alias: RawString<'static> = b"__homm2_data_alias$0000001C$?gConfig@@3UconfigStruct@@A"
            .as_slice()
            .into();
        let mut symbols = BTreeMap::new();
        symbols.insert(0x128d20, owner);
        symbols.insert(0x128d50, alias);
        let contributions = ContributionManifest::default();

        assert!(
            resolve_data_alias(
                &symbols,
                0x128d50,
                0x128d50,
                alias,
                ContributionStorage::Data,
                &contributions,
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_alias_rejects_missing_owner() {
        let alias: RawString<'static> =
            b"__homm2_data_alias$00000030$?notConfig@@3UconfigStruct@@A"
                .as_slice()
                .into();
        let mut symbols = BTreeMap::new();
        symbols.insert(0x128d50, alias);
        let contributions = ContributionManifest::default();

        assert!(
            resolve_data_alias(
                &symbols,
                0x128d50,
                0x128d50,
                alias,
                ContributionStorage::Data,
                &contributions,
            )
            .is_err()
        );
    }
}
