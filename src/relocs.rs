use crate::pdb_symbols;
use crate::utils::ToUsize;
use crate::Env;

use pdb2::RawString;

use object::LittleEndian;
use object::{Object, ObjectSection};

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
pub enum RelocKind<'a> {
    // .text
    Function {
        overloads: &'a [RawString<'static>],
    },

    // .rdata
    ConstantString {
        symbol: RawString<'static>,
        data: &'a [u8],
    },
    ConstantValue {
        target_data: u32,
        maybe_rva: Option<usize>,
    },

    // .data
    // @TODO: Distinguish uninit vs. init statics
    Static {
        symbol: RawString<'static>,
    },
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
                        },
                    );
                }
                () if (env.rdata.rva..env.rdata.rva + env.rdata.size).contains(&target_rva) => {
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
                            let target_data = bytemuck::pod_read_unaligned::<u32>(
                                &exe_data[target_rva..target_rva + 4],
                            );
                            let maybe_rva = target_data
                                .checked_sub(env.image_base)
                                .map(|rva| rva.to_usize());

                            // @TODO
                            coff_data_reloc.copy_from_slice(&0_u32.to_le_bytes());

                            relocs_rva.insert(
                                reloc_rva,
                                RelocKind::ConstantValue {
                                    target_data,
                                    maybe_rva,
                                },
                            );
                        }
                    };
                }
                () if (env.data.rva..env.data.rva + env.data.size).contains(&target_rva) => {
                    let Some((static_rva, static_name)) =
                        symbols.statics.range(..=target_rva).next_back()
                    else {
                        assert_eq!(target_rva, 0, "All relocations must be named");
                        continue;
                    };

                    let diff = u32::try_from(target_rva - *static_rva)?;
                    coff_data_reloc.copy_from_slice(&diff.to_le_bytes());

                    relocs_rva.insert(
                        reloc_rva,
                        RelocKind::Static {
                            symbol: *static_name,
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
