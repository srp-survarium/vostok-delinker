use std::collections::HashMap;

use capstone::Capstone;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{ArchMode, ArchSyntax, X86Operand, X86OperandType};
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};

use object::write::StandardSegment;
use object::{Object, ObjectSection, SectionKind};
use pdb2::FallibleIterator;

const EXECUTABLE: &[u8] = include_bytes!("../resources/survarium.exe");
const DEBUG_SYMBOLS: &[u8] = include_bytes!("../resources/survarium.pdb");

fn main() {
    let exe = object::File::parse(EXECUTABLE).unwrap();
    let pdb = pdb2::PDB::open(std::io::Cursor::new(DEBUG_SYMBOLS)).unwrap();

    let mut object = object::write::Object::new(
        object::BinaryFormat::Coff,
        object::Architecture::I386,
        object::Endianness::Little,
    );

    let data_section_id = object.add_section(vec![], b".data".into(), SectionKind::Data);
    let rdata_section_id = object.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData);
    let text_section_id = object.add_section(vec![], b".text".into(), SectionKind::Text);

    let static_offset = object.append_section_data(
        data_section_id,
        &0x14_u32.to_le_bytes(),
        std::mem::align_of::<u32>() as u64,
    );

    object.add_symbol(object::write::Symbol {
        name: b"s_static_int".to_vec(),
        value: static_offset, // offset of the symbol. Seems like needs to be tracked
        size: u64::MAX,       // seems to be unused for COFF
        kind: object::SymbolKind::Data,
        scope: object::SymbolScope::Compilation,
        weak: false,
        section: object::write::SymbolSection::Section(data_section_id),
        flags: object::SymbolFlags::None,
    });

    //
    //
    //

    let hello_offset = object.append_section_data(
        rdata_section_id,
        b"Hello, World!\n\0",
        std::mem::align_of::<u32>() as u64,
    );
    let bye_offset = object.append_section_data(
        rdata_section_id,
        b"Bye, World!\n\0",
        std::mem::align_of::<u32>() as u64,
    );

    object.add_symbol(object::write::Symbol {
        name: b"$SG3918".to_vec(),
        value: hello_offset, // offset of the symbol. Seems like needs to be tracked
        size: u64::MAX,      // seems to be unused for COFF
        kind: object::SymbolKind::Data,
        scope: object::SymbolScope::Compilation,
        weak: false,
        section: object::write::SymbolSection::Section(rdata_section_id),
        flags: object::SymbolFlags::None,
    });

    object.add_symbol(object::write::Symbol {
        name: b"$SG3919".to_vec(),
        value: bye_offset, // offset of the symbol. Seems like needs to be tracked
        size: u64::MAX,    // seems to be unused for COFF
        kind: object::SymbolKind::Data,
        scope: object::SymbolScope::Compilation,
        weak: false,
        section: object::write::SymbolSection::Section(rdata_section_id),
        flags: object::SymbolFlags::None,
    });

    //
    //
    //

    let fun1_offset = object.append_section_data(
        text_section_id,
        &[
            0x55, 0x8B, 0xEC, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC,
        ],
        std::mem::align_of::<u32>() as u64,
    );

    let fun1_sym = object.add_symbol(object::write::Symbol {
        name: b"?inner@detail@test@@YAXXZ".to_vec(),
        value: fun1_offset, // offset of the symbol. Seems like needs to be tracked
        size: u64::MAX,     // seems to be unused for COFF
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text_section_id),
        flags: object::SymbolFlags::None,
    });

    object
        .add_relocation(
            text_section_id,
            object::write::Relocation {
                offset: fun1_offset,
                size: u8::MAX, // TODO
                kind: object::RelocationKind::Relative,
                encoding: object::RelocationEncoding::Generic,
                symbol: fun1_sym,
                addend: 4,
            },
        )
        .unwrap();

    //
    //
    //

    let object_data = object.write().unwrap();
    std::fs::write(
        "E:\\Projects\\vostok-coff-delinker\\base\\data.obj",
        object_data,
    )
    .unwrap();

    // process_executable(exe, pdb);
}

fn process_executable<S: pdb2::Source<'static> + 'static>(
    exe: object::File,
    pdb: pdb2::PDB<'static, S>,
) {
    let functions = extract_function(exe, pdb).unwrap();

    let capstone = Capstone::new()
        .x86()
        .mode(ArchMode::Mode32)
        .syntax(ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Cannot create Capstone context");
    print_instructions(functions, &capstone);
}

fn print_instructions(exe: Executable, ctx: &Capstone) {
    use capstone::InsnGroupType::*;
    use capstone::arch::x86::X86InsnGroup::*;

    const KNOWN_FUNCTIONS: &[&str] = &[
        // "vostok::render::static_render_model_instance::static_render_model_instance",
        // "btCollisionWorld::RayResultCallback::getShapeId",
        // "vostok::collision::object::object",
        // "vostok::network_core::buffer_to_send",
        // "vostok::animation::bone_names::create_internals_in_place",
    ];

    let iter = exe
        .functions
        .values()
        .filter(|funs| {
            funs.iter()
                .any(|fun| KNOWN_FUNCTIONS.contains(&fun.name.as_str()))
        })
        .map(|funs| &funs[0]);
    // .take(10);

    for fun in iter {
        let disassembleds = ctx
            .disasm_all(&fun.data, fun.address as u64)
            .expect("oopsie");

        // println!(
        //     "\n{} {:#010x} {:#010x} ",
        //     fun.name,
        //     fun.address,
        //     fun.address + fun.data.len()
        // );
        for ix in disassembleds.as_ref() {
            let detail = ctx.insn_detail(ix).unwrap();
            let groups = detail.groups().iter().map(|v| u32::from(v.0));
            let is_branch = groups.clone().any(|v| v == CS_GRP_BRANCH_RELATIVE);

            let mut fn_name = None;
            if is_branch {
                let arch_detail = detail.arch_detail();
                let ops = arch_detail.operands();
                assert_eq!(ops.len(), 1);

                let ArchOperand::X86Operand(X86Operand {
                    op_type: X86OperandType::Imm(target_address),
                    ..
                }) = ops[0]
                else {
                    unreachable!()
                };

                let target_address = usize::try_from(target_address).unwrap();

                let internal_branch =
                    (fun.address..fun.address + fun.data.len()).contains(&target_address);
                if !internal_branch {
                    let target_fun = exe.functions.get(&target_address);

                    if let Some(target_fun) = target_fun {
                        fn_name = Some(target_fun[0].name.clone());
                    } else {
                        // This happens in multiple cases:
                        // * the decompiled assembly is actually not a code, but data (most often jump tables for switches)
                        // * the target points to compiler generated(?) function, which doesn't seem to be in debug files.
                        //  For example, vostok::network_core::http_client::handle_read_content
                        //
                        // This is fine, since this is rare, and we do not care for exact - 100% match of the assembly in all cases.
                    };
                }
            }

            println!(
                "  {:#010x}: {} {}{}",
                ix.address(),
                ix.mnemonic().unwrap_or(""),
                ix.op_str().unwrap_or(""),
                match fn_name {
                    None => format!(""),
                    Some(fn_name) => format!(" | CALLING {fn_name}"),
                },
            )
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Executable {
    pub functions: std::collections::HashMap<usize, Vec<Function>>,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub mangled_name: Option<String>,
    pub address: usize,
    pub data: Vec<u8>,
}

fn extract_function<S: pdb2::Source<'static> + 'static>(
    exe: object::File,
    mut pdb: pdb2::PDB<'static, S>,
) -> Result<Executable, Box<dyn std::error::Error>> {
    let mut res = Executable::default();

    let Some(text_sec) = exe.section_by_name(".text") else {
        return Ok(res);
    };

    //
    //
    //

    let mangled_table = {
        let mut mangled_table = HashMap::<usize, Vec<String>>::new();

        let symbol_table = pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb2::SymbolData::Public(data)) if data.function => {
                    let offset = data.offset.offset as usize;
                    mangled_table
                        .entry(offset)
                        .or_default()
                        .push(data.name.to_string().to_string());
                }
                _ => {}
            }
        }
        mangled_table
    };

    //
    //
    //

    let text_section_address = text_sec.address() as usize;
    println!("TEXT SECTION ADDRESS {:#010x}", text_section_address);
    let text_data = text_sec.data()?;

    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;

    while let Some(module) = modules.next()? {
        if let Some(module_info) = pdb.module_info(&module)? {
            let mut iter = module_info.symbols()?;

            let mut add_function_from_pdb =
                |name: pdb2::RawString, offset: pdb2::PdbInternalSectionOffset, len: u32| {
                    let name = name.to_string().to_string();
                    let offset = offset.offset as usize;
                    let len = len as usize;

                    if len == 0 {
                        todo!()
                    }

                    let mangled_name = match mangled_table.get(&offset) {
                        Some(symbols) => Some(symbols[0].to_string()),
                        None => None,
                    };
                    let address = text_section_address + offset;
                    let data = text_data[offset..offset + len].to_vec();

                    res.functions.entry(address).or_default().push(Function {
                        name,
                        mangled_name,
                        address,
                        data,
                    })
                };

            while let Some(symbol) = iter.next()? {
                match symbol.parse() {
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => {
                        add_function_from_pdb(name, offset, len);
                    }
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        offset, len, name, ..
                    })) => {
                        add_function_from_pdb(name, offset, len.into());
                    }
                    _ => (),
                }
            }
        }
    }

    Ok(res)
}
