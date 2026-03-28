use std::collections::HashMap;

use capstone::arch::x86::{ArchMode, ArchSyntax};
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::Capstone;

use object::{Object, ObjectSection};
use pdb2::FallibleIterator;

const EXECUTABLE: &[u8] = include_bytes!("../resources/survarium.exe");
const DEBUG_SYMBOLS: &[u8] = include_bytes!("../resources/survarium.pdb");

fn main() {
    let exe = object::File::parse(EXECUTABLE).unwrap();
    let pdb = pdb2::PDB::open(std::io::Cursor::new(DEBUG_SYMBOLS)).unwrap();

    process_executable(exe, pdb);
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
type FilteredInstructions = Vec<u8>;
fn filter_instructions(exe: Executable, capstone: &Capstone) -> FilteredInstructions {
    for (_, fns) in &exe.functions {
        for fun in fns {
            if !fun.name.starts_with("vostok::") && !fun.name.starts_with("survarium::") {
                continue;
            }
            let disassembleds = capstone
                .disasm_all(&fun.data, fun.address as u64)
                .expect("oopsie");
            println!("{}  ", fun.name);
            if fun.name.starts_with("vostok") || fun.name.starts_with("survarium") {
                for disassembled in disassembleds.as_ref() {
                    println!(
                        "  {:#010x}: {} {}",
                        disassembled.address(),
                        disassembled.mnemonic().unwrap_or(""),
                        disassembled.op_str().unwrap_or("")
                    );
                }
            }
        }
    }
}
fn print_instructions(exe: Executable, capstone: &Capstone) {
    for (_, fns) in &exe.functions {
        for fun in fns {
            if !fun.name.starts_with("vostok::") && !fun.name.starts_with("survarium::") {
                continue;
            }
            let disassembleds = capstone
                .disasm_all(&fun.data, fun.address as u64)
                .expect("oopsie");
            println!("{}  ", fun.name);
            if fun.name.starts_with("vostok") || fun.name.starts_with("survarium") {
                for disassembled in disassembleds.as_ref() {
                    println!(
                        "  {:#010x}: {} {}",
                        disassembled.address(),
                        disassembled.mnemonic().unwrap_or(""),
                        disassembled.op_str().unwrap_or("")
                    );
                }
            }
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

                    res.functions.entry(offset).or_default().push(Function {
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
