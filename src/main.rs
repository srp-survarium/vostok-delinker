#![feature(os_string_truncate)]

use std::collections::{btree_map, BTreeMap, HashMap};

use capstone::arch::x86::{ArchMode, ArchSyntax, X86Operand, X86OperandType};
use capstone::arch::ArchOperand;
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::Capstone;
use capstone::InsnGroupType::*;

use clap::Parser;
use object::{LittleEndian, SectionKind};
use object::{Object, ObjectSection};

use pdb2::{FallibleIterator, RawString};

#[derive(clap::Parser)]
pub struct Cli {
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub pdb_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub exe_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub output_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub engine_path: String,
}

pub struct ObjectFiles<'a> {
    pub objects: HashMap<&'a [u8], ObjectFile>,
}

pub struct ObjectFile {
    pub object: object::write::Object<'static>,
    pub data_section_id: object::write::SectionId,
    pub rdata_section_id: object::write::SectionId,
    pub text_section_id: object::write::SectionId,
}

#[derive(Clone, Debug, Default, Copy)]
pub struct SecInfo<'a> {
    pub rva: usize,
    pub va: usize,

    pub size: usize,
    pub id: u16,

    pub data: &'a [u8],
}

// # Notes
//
// ## 6. sushi@TODO: Relocations in .data and .rdata
// ## 7. sushi@TODO: Initialized statics in .rdata

fn main() -> anyhow::Result<()> {
    let Cli {
        pdb_path,
        exe_path,
        output_path,
        engine_path,
    } = Cli::parse();

    let exe: &[u8] = std::fs::read(exe_path)?.leak();
    let exe = object::read::pe::PeFile32::parse(exe)?;
    let exe: &'static object::read::pe::PeFile32 = leak(exe);

    let pdb = std::fs::read(pdb_path)?.leak();
    let pdb = std::io::Cursor::new(pdb);
    let pdb = pdb2::PDB::open(pdb)?;

    let mut engine_path = engine_path.to_lowercase().replace('/', "\\");
    if !engine_path.ends_with('\\') {
        engine_path.push('\\');
    }

    process_executable(exe, pdb, engine_path.as_bytes(), output_path.as_path())?;

    Ok(())
}

fn process_executable<S: pdb2::Source<'static> + 'static>(
    exe: &'static object::read::pe::PeFile32<'static>,
    pdb: pdb2::PDB<'static, S>,
    engine_path: &[u8],
    output_path: &std::path::Path,
) -> anyhow::Result<()> {
    let object_files = ObjectFiles::parse(exe, pdb, engine_path)?;
    object_files.write(output_path)?;

    Ok(())
}

impl ObjectFiles<'static> {
    fn parse<S: pdb2::Source<'static> + 'static>(
        exe: &'static object::read::pe::PeFile32<'static>,
        mut pdb: pdb2::PDB<'static, S>,
        engine_path: &[u8],
    ) -> anyhow::Result<ObjectFiles<'static>> {
        let image_base = exe
            .nt_headers()
            .optional_header
            .image_base
            .get(LittleEndian);

        let dbi = leak(pdb.debug_information()?);
        let string_table: &'static pdb2::StringTable<'static> = leak(pdb.string_table()?);

        let build_sec_info = |sec: object::read::pe::PeSection<'static, 'static, _>| {
            Ok::<_, anyhow::Error>(SecInfo {
                rva: sec.address() as usize - image_base as usize,
                va: sec.address() as usize,

                size: sec.size() as usize,
                id: sec.index().0 as u16,

                data: sec.data()?,
            })
        };

        let Some(text_sec) = exe.section_by_name(".text") else {
            anyhow::bail!("Missing .text section");
        };
        let Some(rdata_sec) = exe.section_by_name(".rdata") else {
            anyhow::bail!("Missing .rdata section");
        };
        let Some(data_sec) = exe.section_by_name(".data") else {
            anyhow::bail!("Missing .data section");
        };

        let text = build_sec_info(text_sec)?;
        let rdata = build_sec_info(rdata_sec)?;
        let data = build_sec_info(data_sec)?;

        //
        // rva, offset, address
        //

        let mut functions = BTreeMap::<usize, Vec<RawString>>::new();
        let mut statics = BTreeMap::<usize, RawString>::new();
        let mut strings = BTreeMap::<usize, (RawString, Vec<u8>)>::new();

        {
            let symbol_table: &'static pdb2::SymbolTable = leak(pdb.global_symbols()?);

            // Additional non-mangled constants from `Data` symbols.
            // Only used for symbols not found in `Public` symbols.
            // (@NOTE: might be useless, we will see)
            let mut data_statics = vec![];

            let mut symbols = symbol_table.iter();
            while let Some(symbol) = symbols.next()? {
                match symbol.parse() {
                    Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol {
                        function,
                        offset,
                        name,
                        ..
                    })) if function => {
                        assert_eq!(offset.section, text.id);

                        let offset = offset.offset as usize;

                        functions.entry(offset).or_default().push(name);
                    }

                    Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }))
                        if offset.section == rdata.id && name.as_bytes().starts_with(b"??_C@_") =>
                    {
                        let offset = offset.offset as usize;

                        let msvc_demangler::Type::ConstantString(string) =
                            msvc_demangler::parse(&name.to_string())?.symbol_type
                        else {
                            continue;
                        };

                        let result = strings.insert(offset, (name, string));
                        assert_eq!(result, None);
                    }

                    Ok(pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, name, .. }))
                        if offset.section == data.id =>
                    {
                        let offset = offset.offset as usize;

                        let old_value = statics.insert(offset, name);
                        if let Some(value) = old_value {
                            anyhow::bail!(
                                "Conflict at offset {offset:x?} between '{value}' and '{name}'"
                            );
                        }
                    }

                    // Ignored for now.
                    // There are not that many symbols and the ones with types are either U64 or F80.
                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, .. }))
                        if offset.section == rdata.id => {}

                    // in public they are mangled
                    // in data all symbols are not mangled, yes
                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, name, .. }))
                        if offset.section == data.id =>
                    {
                        let offset = offset.offset as usize;

                        data_statics.push((offset, name));
                    }
                    _ => {}
                }
            }

            for (offset, name) in data_statics {
                let entry = statics.entry(offset);
                match entry {
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert(name);
                    }
                    _ => (),
                }
            }
        };

        {
            let mut modules = dbi.modules()?;

            while let Some(module) = modules.next()? {
                let Some(module_info) = pdb.module_info(&module)? else {
                    continue;
                };
                let module_info = leak(module_info);

                let mut iter = module_info.symbols()?;

                while let Some(symbol) = iter.next()? {
                    let (size, name, offset) = match symbol.parse() {
                        Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                            len,
                            name,
                            offset,
                            ..
                        })) => (len, name, offset),
                        Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                            len,
                            offset,
                            name,
                            ..
                        })) => (len as u32, name, offset),
                        _ => continue,
                    };

                    let fun_offset_in_text = offset.offset as usize;
                    let fun_body =
                        &text.data[fun_offset_in_text..fun_offset_in_text + size as usize];

                    #[rustfmt::skip]
                    const COMMON_FUNCTION_RENAMES: &[(&[u8], &[u8])] = &[
                        (b"empty_stub", &[0xC3]),
                        (b"identity",   &[0x8B, 0x44, 0x24, 0x04, 0xC3]),
                        (b"vec_begin",  &[0x8B, 0x0, 0xC3]),
                        (b"vec_size",   &[0x8B, 0x41, 0x04, 0x2B, 0x01, 0xC1, 0xF8, 0x02, 0xC3]),
                    ];

                    let fun_rename = COMMON_FUNCTION_RENAMES
                        .iter()
                        .find(|(_, code)| *code == fun_body)
                        .map(|(name, _)| (*name).into());

                    match functions.entry(fun_offset_in_text) {
                        btree_map::Entry::Vacant(entry) => {
                            entry.insert(vec![fun_rename.unwrap_or(name)]);
                        }
                        btree_map::Entry::Occupied(mut entry) => match fun_rename {
                            Some(fun_rename) => *entry.get_mut() = vec![fun_rename],
                            None => (),
                        },
                    }
                }
            }
        }

        //
        // Fix all relocations in the text section of the executable.
        // @NOTE: They can be in other parts
        //

        enum RelocKind<'a> {
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
                data: [u8; 4], // first 4 bytes
            },

            // .data
            // @TODO: Distinguish uninit vs. init statics
            Static {
                symbol: RawString<'static>,
            },
        }

        let mut text_sec_data = text.data.to_vec();
        let mut text_relocs = BTreeMap::<usize, RelocKind>::new();

        let Some(reloc_sec) = exe.section_by_name(".reloc") else {
            anyhow::bail!("Missing .reloc section");
        };

        {
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

            let mut pos = 0;
            let reloc_data = reloc_sec.data()?;
            while pos + HEADER_SIZE <= reloc_data.len() {
                let RelocHeader {
                    page_rva,
                    block_size,
                } = bytemuck::pod_read_unaligned(&reloc_data[pos..pos + HEADER_SIZE]);

                if block_size == 0 || block_size < 8 {
                    break;
                }

                let entries: &[RelocEntry] =
                    bytemuck::cast_slice(&reloc_data[pos + HEADER_SIZE..pos + block_size as usize]);
                pos += block_size as usize;

                for RelocEntry { entry } in entries {
                    let reloc_type = entry >> 12;
                    let reloc_offset = entry & 0x0FFF;

                    const RELOC_TYP_HIGHLOW: u16 = 3;

                    if reloc_type != RELOC_TYP_HIGHLOW {
                        continue;
                    }

                    let reloc_rva = (page_rva + u32::from(reloc_offset)) as usize;
                    let in_text = (text.rva..text.rva + text.size).contains(&reloc_rva);

                    // @TODO: this is that "cornercase"
                    if !in_text {
                        continue;
                    }

                    let offset_in_text = (reloc_rva - text.rva) as usize;
                    let target_va: u32 = bytemuck::pod_read_unaligned(
                        &text_sec_data[offset_in_text..offset_in_text + 4],
                    );
                    let target_va = target_va as usize;

                    match () {
                        () if (text.va..text.va + text.size).contains(&target_va) => {
                            let target_offset_in_text = target_va - text.va;

                            let (function_offset_in_text, function_overloads) = functions
                                .range(..=target_offset_in_text)
                                .next_back()
                                .expect("all function relocs to be named");

                            text_sec_data[offset_in_text..offset_in_text + 4].copy_from_slice(
                                &u32::to_le_bytes(
                                    (target_offset_in_text - *function_offset_in_text) as u32,
                                ),
                            );
                            text_relocs.insert(
                                offset_in_text,
                                RelocKind::Function {
                                    overloads: function_overloads,
                                },
                            );
                        }
                        () if (rdata.va..rdata.va + rdata.size).contains(&target_va) => {
                            let target_offset_in_rdata = target_va - rdata.va;

                            match strings.range(..=target_offset_in_rdata).next_back() {
                                Some((string_offset_in_rdata, (string_mangled_name, string)))
                                    if target_offset_in_rdata - string_offset_in_rdata
                                        < string.len() =>
                                {
                                    text_sec_data[offset_in_text..offset_in_text + 4]
                                        .copy_from_slice(&u32::to_le_bytes(
                                            (target_offset_in_rdata - *string_offset_in_rdata)
                                                as u32,
                                        ));

                                    text_relocs.insert(
                                        offset_in_text,
                                        RelocKind::ConstantString {
                                            symbol: *string_mangled_name,
                                            data: string,
                                        },
                                    );
                                }

                                Some(_) | None => {
                                    text_sec_data[offset_in_text..offset_in_text + 4]
                                        .copy_from_slice(&u32::to_le_bytes(0));

                                    text_relocs.insert(
                                        offset_in_text,
                                        RelocKind::ConstantValue {
                                            data: bytemuck::pod_read_unaligned(
                                                &rdata.data[target_offset_in_rdata
                                                    ..target_offset_in_rdata + 4],
                                            ),
                                        },
                                    );
                                }
                            };
                        }
                        () if (data.va..data.va + data.size).contains(&target_va) => {
                            let target_offset_in_data = target_va - data.va;

                            let Some((static_offset_in_data, static_name)) =
                                statics.range(..=target_offset_in_data).next_back()
                            else {
                                if target_offset_in_data == 0 {
                                    continue;
                                }
                                panic!("all static relocs to be named");
                            };

                            text_sec_data[offset_in_text..offset_in_text + 4].copy_from_slice(
                                &u32::to_le_bytes(
                                    (target_offset_in_data - *static_offset_in_data) as u32,
                                ),
                            );
                            text_relocs.insert(
                                offset_in_text,
                                RelocKind::Static {
                                    symbol: *static_name,
                                },
                            );
                        }
                        () => (),
                    }
                }
            }
        }

        let mut object_files = ObjectFiles {
            objects: HashMap::new(),
        };
        {
            let ctx = Capstone::new()
                .x86()
                .mode(ArchMode::Mode32)
                .syntax(ArchSyntax::Intel)
                .detail(true)
                .build()
                .expect("Cannot create Capstone context");

            let mut modules = dbi.modules()?;
            while let Some(module) = modules.next()? {
                let Some(module_info) = pdb.module_info(&module)? else {
                    continue;
                };
                let module_info = leak(module_info);

                let program = module_info.line_program()?;
                let mut iter = module_info.symbols()?;

                while let Some(symbol) = iter.next()? {
                    let (name, offset, size) = match symbol.parse() {
                        Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                            name,
                            offset,
                            len,
                            ..
                        })) => (name, offset, len),
                        Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                            offset,
                            len,
                            name,
                            ..
                        })) => (name, offset, len.into()),
                        _ => continue,
                    };

                    let mut filename = None;

                    let mut lines = program.lines_for_symbol(offset);
                    // Extracting only a single line should be enough to find a source file.
                    if let Some(line_info) = lines.next()? {
                        let file_info = program.get_file_info(line_info.file_index)?;
                        filename = Some(string_table.get(file_info.name)?);
                    }

                    let filename: &'static [u8] = match filename {
                        Some(filename) => match filename.as_bytes().strip_prefix(engine_path) {
                            Some(filename) => filename,
                            None => continue,
                        },
                        None => match name.as_bytes() {
                            name if !contains(name, b"::") && !name.contains(&b' ') => {
                                b"_msvc_internal\\c_lang"
                            }
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

                    //
                    //
                    //

                    let fun_offset_in_text = offset.offset as usize;
                    let fun_size = size as usize;

                    let fun_range_in_text = fun_offset_in_text..fun_offset_in_text + fun_size;
                    let fun_va = text.va + fun_offset_in_text;

                    let mut fun_bytes = text_sec_data[fun_range_in_text.clone()].to_vec();
                    let mut offset_in_fun = 0;

                    let ixs =
                        ctx.disasm_all(&text_sec_data[fun_range_in_text.clone()], fun_va as u64)?;
                    for ix in ixs.iter() {
                        let detail = ctx.insn_detail(ix)?;
                        let arch_detail = detail.arch_detail();

                        let groups = detail.groups().iter().map(|v| u32::from(v.0));

                        let is_branch = groups.clone().any(|v| v == CS_GRP_BRANCH_RELATIVE);

                        if !is_branch {
                            offset_in_fun += ix.len();
                            continue;
                        }

                        let ops = arch_detail.operands();
                        assert_eq!(ops.len(), 1);

                        let ArchOperand::X86Operand(X86Operand {
                            op_type: X86OperandType::Imm(target_va),
                            ..
                        }) = ops[0]
                        else {
                            unreachable!()
                        };
                        let internal_branch =
                            (fun_va..fun_va + fun_size).contains(&(target_va as usize));
                        if internal_branch {
                            offset_in_fun += ix.len();
                            continue;
                        }

                        match functions.get(&(target_va as usize - text.va)) {
                            Some(overloads) if ix.len() > 4 => {
                                offset_in_fun += ix.len() - 4;
                                fun_bytes[offset_in_fun..offset_in_fun + 4]
                                    .copy_from_slice(&0_u32.to_le_bytes());

                                let result = text_relocs.insert(
                                    fun_offset_in_text + offset_in_fun,
                                    RelocKind::Function { overloads },
                                );
                                offset_in_fun += 4;

                                if let Some(result) = result {
                                    let RelocKind::Function {
                                        overloads: old_overloads,
                                    } = result
                                    else {
                                        unreachable!();
                                    };
                                    assert_eq!(overloads.as_ptr(), old_overloads.as_ptr());
                                }
                            }
                            // Data parsed as intruction.
                            // Often happens for jump tables located at the end.
                            // See: `vostok::render::stage_sun::execute`.
                            //
                            // sushi@TODO: Figure out better implementation.
                            Some(_) | None => {
                                offset_in_fun += ix.len();
                            }
                        }
                    }

                    //
                    //
                    //

                    let object_file = object_files.objects.entry(filename).or_insert_with(|| {
                        let mut object = object::write::Object::new(
                            object::BinaryFormat::Coff,
                            object::Architecture::I386,
                            object::Endianness::Little,
                        );

                        let data_section_id =
                            object.add_section(vec![], b".data".into(), SectionKind::Data);
                        let rdata_section_id =
                            object.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData);
                        let text_section_id =
                            object.add_section(vec![], b".text".into(), SectionKind::Text);

                        // objdiff considers allocations to match if name is equal OR(!) offset
                        // into reloc table is the same.
                        //
                        // This makes different relocations with different data and different names
                        // to match, if they offsets match. These 4 bytes prevent that.
                        if engine_path == b"c:\\survarium\\sources\\" {
                            object.append_section_data(rdata_section_id, &0_u32.to_le_bytes(), 4);
                        }

                        ObjectFile {
                            object,
                            data_section_id,
                            rdata_section_id,
                            text_section_id,
                        }
                    });

                    let ObjectFile {
                        object,
                        data_section_id: _,
                        rdata_section_id,
                        text_section_id,
                    } = object_file;

                    let fun_offset_in_coff =
                        append_with_padding(object, *text_section_id, &fun_bytes, 0x90);

                    for (reloc_offset_in_text, reloc_kind) in text_relocs.range(fun_range_in_text) {
                        let reloc_offset_in_text = *reloc_offset_in_text as u64;
                        match reloc_kind {
                            RelocKind::Static { symbol: reloc_name } => {
                                let reloc_symbol = object.add_symbol(object::write::Symbol {
                                    name: reloc_name.as_bytes().to_vec(),
                                    value: 0,
                                    size: u64::MAX,
                                    kind: object::SymbolKind::Unknown,
                                    scope: object::SymbolScope::Linkage,
                                    weak: false,
                                    section: object::write::SymbolSection::Undefined,
                                    flags: object::SymbolFlags::None,
                                });

                                let reloc_offset_in_fun =
                                    reloc_offset_in_text - fun_offset_in_text as u64;
                                object.add_relocation(
                                    *text_section_id,
                                    object::write::Relocation {
                                        offset: fun_offset_in_coff + reloc_offset_in_fun,
                                        symbol: reloc_symbol,
                                        addend: -4,
                                        //  zedddie@FIXME: ^^ this seem to be true only for movs/jmps, not for pushes
                                        flags: object::RelocationFlags::Generic {
                                            kind: object::RelocationKind::Relative,
                                            encoding: object::RelocationEncoding::Generic,
                                            size: 32,
                                        },
                                    },
                                )?;
                            }
                            RelocKind::Function { overloads } => {
                                let reloc_name = find_closest_relative_call(&name, overloads);

                                let reloc_symbol = object.add_symbol(object::write::Symbol {
                                    name: reloc_name.as_bytes().to_vec(),
                                    value: 0,
                                    size: u64::MAX,
                                    kind: object::SymbolKind::Unknown,
                                    scope: object::SymbolScope::Linkage,
                                    weak: false,
                                    section: object::write::SymbolSection::Undefined,
                                    flags: object::SymbolFlags::None,
                                });

                                let reloc_offset_in_fun =
                                    reloc_offset_in_text - fun_offset_in_text as u64;
                                object.add_relocation(
                                    *text_section_id,
                                    object::write::Relocation {
                                        offset: fun_offset_in_coff + reloc_offset_in_fun,
                                        symbol: reloc_symbol,
                                        addend: -4,
                                        //  zedddie@FIXME: ^^ this seem to be true only for movs/jmps, not for pushes
                                        flags: object::RelocationFlags::Generic {
                                            kind: object::RelocationKind::Relative,
                                            encoding: object::RelocationEncoding::Generic,
                                            size: 32,
                                        },
                                    },
                                )?;
                            }
                            RelocKind::ConstantValue { data } => {
                                // sushi@TODO: data might be reloc as well, so needs to be handled properly
                                let reloc_name =
                                    format!("?value_0x{:x?}@@3IA", u32::from_le_bytes(*data));

                                let const_offset_in_coff =
                                    append_with_padding(object, *rdata_section_id, data, 0x00);

                                let reloc_symbol = object.add_symbol(object::write::Symbol {
                                    name: reloc_name.as_bytes().to_vec(),
                                    value: const_offset_in_coff,
                                    size: u64::MAX,
                                    kind: object::SymbolKind::Data,
                                    scope: object::SymbolScope::Linkage,
                                    weak: false,
                                    section: object::write::SymbolSection::Section(
                                        *rdata_section_id,
                                    ),
                                    flags: object::SymbolFlags::None,
                                });

                                let reloc_offset_in_fun =
                                    reloc_offset_in_text - fun_offset_in_text as u64;
                                object.add_relocation(
                                    *text_section_id,
                                    object::write::Relocation {
                                        offset: fun_offset_in_coff + reloc_offset_in_fun,
                                        symbol: reloc_symbol,
                                        addend: -4,
                                        //  zedddie@FIXME: ^^ this seem to be true only for movs/jmps, not for pushes
                                        flags: object::RelocationFlags::Generic {
                                            kind: object::RelocationKind::Relative,
                                            encoding: object::RelocationEncoding::Generic,
                                            size: 32,
                                        },
                                    },
                                )?;
                            }
                            RelocKind::ConstantString { symbol, data } => {
                                let reloc_name = match () {
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
                                        .map(|c| {
                                            match c[0] == b'0' && c[1].is_ascii_alphanumeric() {
                                                true => c[1],
                                                false => b'_',
                                            }
                                        })
                                        .collect::<Vec<_>>(),
                                    () => unreachable!(),
                                };

                                let const_offset_in_coff =
                                    append_with_padding(object, *rdata_section_id, data, 0x00);

                                let reloc_symbol = object.add_symbol(object::write::Symbol {
                                    name: reloc_name,
                                    value: const_offset_in_coff,
                                    size: u64::MAX,
                                    kind: object::SymbolKind::Data,
                                    scope: object::SymbolScope::Linkage,
                                    weak: false,
                                    section: object::write::SymbolSection::Section(
                                        *rdata_section_id,
                                    ),
                                    flags: object::SymbolFlags::None,
                                });

                                let reloc_offset_in_fun =
                                    reloc_offset_in_text - fun_offset_in_text as u64;
                                object.add_relocation(
                                    *text_section_id,
                                    object::write::Relocation {
                                        offset: fun_offset_in_coff + reloc_offset_in_fun,
                                        symbol: reloc_symbol,
                                        addend: -4,
                                        //  zedddie@FIXME: ^^ this seem to be true only for movs/jmps, not for pushes
                                        flags: object::RelocationFlags::Generic {
                                            kind: object::RelocationKind::Relative,
                                            encoding: object::RelocationEncoding::Generic,
                                            size: 32,
                                        },
                                    },
                                )?;
                            }
                        }
                    }

                    let name = match functions.get(&fun_offset_in_text) {
                        Some(overloads) => find_closest_symbol_name(&name, overloads),
                        None => name,
                    };
                    object.add_symbol(object::write::Symbol {
                        name: name.as_bytes().to_vec(),

                        value: fun_offset_in_coff,
                        size: u64::MAX,
                        kind: object::SymbolKind::Text,
                        scope: object::SymbolScope::Linkage,
                        weak: false,
                        section: object::write::SymbolSection::Section(*text_section_id),
                        flags: object::SymbolFlags::None,
                    });
                }
            }
        }

        Ok(object_files)
    }

    fn write(self, base: &std::path::Path) -> anyhow::Result<()> {
        let base_len = base.as_os_str().as_encoded_bytes().len();
        let mut path = base.to_path_buf();

        for (prefix, object_file) in self.objects {
            path.as_mut_os_string().truncate(base_len);

            let prefix = prefix
                .iter()
                .map(|&c| match c {
                    b'\\' => '/',
                    _ => c as char,
                })
                .collect::<String>();
            path.as_mut_os_string().push("/");
            path.as_mut_os_string().push(&prefix);
            path.as_mut_os_string().push(".obj");

            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, object_file.object.write()?)?;
        }
        Ok(())
    }
}

// Most of those leaks have to exist to "leak" Streams which for some reason are owning in pdb crate.
fn leak<T>(object: T) -> &'static T {
    Box::leak(Box::new(object))
}

// Always pads to 4
fn append_with_padding(
    object: &mut object::write::Object,
    section_id: object::write::SectionId,
    data: &[u8],
    pad: u8,
) -> u64 {
    let offset = object.append_section_data(section_id, data, 1);

    // sushi@TODO: `object` crate doesn't(?) allow specifying auxiliary symbols.
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

fn last_segment_no_generics(name: &[u8]) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut end = name.len();
    for (i, &c) in name.iter().enumerate().rev() {
        match c {
            b'>' => depth += 1,
            b'<' => {
                if depth == 1 {
                    end = i;
                }
                depth = depth.checked_sub(1)?;
            }
            b':' if depth == 0 && name.get(i + 1) == Some(&b':') => {
                let start = i + b"::".len();
                if start >= end {
                    return None;
                }
                return Some((start, end));
            }
            _ if depth == 0 && i == 0 => return Some((0, end)),
            _ => {}
        }
    }
    None
}

fn find_closest_relative_call<'p>(
    fun_name: &RawString,
    overloads: &[RawString<'p>],
) -> RawString<'p> {
    match overloads.len() {
        1 => overloads[0],
        _ => find_closest_symbol(get_class(fun_name.as_bytes()), overloads.iter()),
    }
}

fn find_closest_symbol_name<'p>(
    fun_name: &RawString,
    overloads: &[RawString<'p>],
) -> RawString<'p> {
    match overloads.len() {
        1 => overloads[0],
        _ => find_closest_symbol(get_method(fun_name.as_bytes()), overloads.iter()),
    }
}

fn get_class(name: &[u8]) -> Option<&[u8]> {
    let (fn_start, _) = last_segment_no_generics(name)?;

    let class_end = fn_start.checked_sub(b"::".len())?;
    let path = &name[..class_end];

    let (class_start, class_end) = last_segment_no_generics(path)?;
    Some(&path[class_start..class_end])
}

fn get_method(name: &[u8]) -> Option<&[u8]> {
    let (fn_start, fn_end) = last_segment_no_generics(name)?;
    Some(&name[fn_start..fn_end])
}

fn find_closest_symbol<'a, 'p, I>(name: Option<&[u8]>, mangled_symbols: I) -> RawString<'p>
where
    I: Iterator<Item = &'a RawString<'p>> + Clone,
    'p: 'a,
{
    if let Some(name) = name {
        if let Some(sym) = mangled_symbols
            .clone()
            .filter(|sym| sym.as_bytes().windows(name.len()).any(|sym| sym == name))
            .min_by_key(|sym| sym.len())
        {
            return *sym;
        }
    }
    *mangled_symbols
        .min_by_key(|sym| sym.len())
        .expect("Mangled iterator to not be empty")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|s| s == needle)
}
