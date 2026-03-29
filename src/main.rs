#![expect(dead_code)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_variables)]

use std::borrow::Cow;
use std::collections::HashMap;

use capstone::arch::x86::X86InsnGroup::*;
use capstone::arch::x86::{ArchMode, ArchSyntax, X86Operand, X86OperandType};
use capstone::arch::ArchOperand;
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::Capstone;
use capstone::InsnGroupType::*;

use object::write::StandardSegment;
use object::{Object, ObjectSection, SectionKind};
use pdb2::{FallibleIterator, RawString};

const EXECUTABLE: &[u8] = include_bytes!("../resources/survarium.exe");
const DEBUG_SYMBOLS: &[u8] = include_bytes!("../resources/survarium.pdb");

pub struct ObjectFiles<'a> {
    pub objects: std::collections::HashMap<&'a [u8], object::write::Object<'static>>,
}

#[derive(Clone, Default, Debug)]
pub struct Executable<'a> {
    // `HashMap` was chosen, because we need to make lookups
    // based on what function calls or jumps to.
    //
    // `Vec` is always `NonEmpty`.
    pub functions: std::collections::HashMap<usize, Vec<Function<'a>>>,
    // constants?
    // statics?
}

#[derive(Clone, Debug)]
pub struct Function<'a> {
    pub name: RawString<'a>,
    pub mangled_name: Option<RawString<'a>>,
    pub filename: Option<RawString<'a>>,

    pub address: usize,

    pub data: &'a [u8],
}

// # Notes
//
// ## On object file structure
// Since there were no proper object files, because of LTO, we will be basing everything on our own structure.
//
// There are multiple ways to separate them:
// 1. Based on file structure.
//  +. Gets as close to matching code based on original object files as possible.
//  +. We have PDB files containing that information.
//  -. Compiler generated methods usually do not have source file specified.
//
// 2. Based on class hierarchy:
//  +. Easy to navigate and search for.
//  -. Harder to figure out the structure for free functions, which might also be static and which
//      might not even have namespaces.
//  -. Requires parsing mangled symbols.
//
// I prefer the first option with the second one being used for compiler generated symbols.
//
// ## Current problems
// 1. Mangled symbols are taken incorrectly, since we have no way to properly disambiguate them.
//  =. We can try to find in mangled symbols function name. Might solve the problem somewhat.
//  =. Are mangled symbols even needed?
//
// 2. Jump symbols suffer the same problem.
//  =. The solution is to not be exactly correct, but be exact when comparing `base` and `target`.
//  =. I like optimization of taking the smallest symbol available for `target`.
//  =. Or by first searching whether there is a symbol with the same class name.
//  =. Base should just default to what target picked, and use those "optimizations", if nothing was matching.
//
// 3. `object` crate always prepends '_' to all symbols. Which is incorrect for C++ mangling scheme.
//  =. Fork or just ignore the problem.
//
// 4. What should be done about functions with the same assembly but with different symbols?
//  =. They should all be their own separate functions.
//
// 5. What should be even parsed?
//  =. We need metrics for specific `vostok` and `survarium` modules for server code.
//  =. We most likely DON'T need anything in boost or Scaleform. All of that just takes precious time.
//  =. We might still want `bullet` functions, since devs were updating its source code manually.

fn main() {
    let exe = object::File::parse(EXECUTABLE).unwrap();
    let pdb = pdb2::PDB::open(std::io::Cursor::new(DEBUG_SYMBOLS)).unwrap();

    // play_with_demangler();
    process_executable(exe, pdb).unwrap();
    // build_dummy_object_file();
}

fn play_with_demangler() {
    let mangled_names = [
        "??0box_geometry_instance@collision@vostok@@QAE@ABVfloat4x4@math@2@@Z",
        "??1box_geometry_instance@collision@vostok@@UAE@XZ",
        "??_Gbox_geometry_instance@collision@vostok@@UAEPAXI@Z",
        "?aabb_test@box_geometry_instance@collision@vostok@@UBE_NABVaabb@math@3@@Z",
    ];
    for mangled_name in mangled_names {
        let name =
            msvc_demangler::demangle(mangled_name, msvc_demangler::DemangleFlags::empty()).unwrap();
        println!("{name}");

        let data = msvc_demangler::parse(mangled_name).unwrap();
        println!("{data:#?}\n");
    }
}

fn build_dummy_object_file() {
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

    //

    #[rustfmt::skip]
    let fun2_offset = object.append_section_data(
        text_section_id,
        &[
            0x55, 0x8B, 0xEC,              // prolog -- push ebp ; mov ebp, esp
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call   -- call ?inner
            0xE8, 0x00, 0x00, 0x00, 0x00,  // call   -- call ?inner
            0x5D, 0xC3, 0xCC,              // epilog -- pop ebp ; ret ; int3
        ],
        std::mem::align_of::<u32>() as u64,
    );

    let fun2_sym = object.add_symbol(object::write::Symbol {
        name: b"?print_hello2@@YAXXZ".to_vec(),
        value: fun2_offset, // offset of the symbol. Seems like needs to be tracked
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
                offset: fun2_offset + 4,
                size: 32,
                kind: object::RelocationKind::Relative,
                encoding: object::RelocationEncoding::Generic,
                symbol: fun1_sym,
                addend: -4,
            },
        )
        .unwrap();

    object
        .add_relocation(
            text_section_id,
            object::write::Relocation {
                offset: fun2_offset + 9,
                size: 32,
                kind: object::RelocationKind::Relative,
                encoding: object::RelocationEncoding::Generic,
                symbol: fun1_sym,
                addend: -4,
            },
        )
        .unwrap();

    //
    //
    //

    let object_data = object.write().unwrap();
    std::fs::write("./objdiff/base/data.obj", object_data).unwrap();
}

fn process_executable<S: pdb2::Source<'static> + 'static>(
    exe: object::File<'static>,
    pdb: pdb2::PDB<'static, S>,
) -> anyhow::Result<()> {
    let ctx = Capstone::new()
        .x86()
        .mode(ArchMode::Mode32)
        .syntax(ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Cannot create Capstone context");

    let exe: &'static object::File = leak(exe);

    Executable::parse(exe, pdb)?.build_object_files(&ctx)?;

    Ok(())
}

impl<'a: 'static> Executable<'a> {
    fn parse<S: pdb2::Source<'static> + 'static>(
        exe: &'static object::File,
        mut pdb: pdb2::PDB<'static, S>,
    ) -> anyhow::Result<Self> {
        let mut this = Self::default();

        let Some(text_sec) = exe.section_by_name(".text") else {
            return Ok(this);
        };

        let text_section_address = text_sec.address() as usize;
        let text_data = text_sec.data()?;

        //
        //
        //

        let symbol_table: &'static pdb2::SymbolTable<'static> = leak(pdb.global_symbols()?);
        let mangled_table = {
            let mut symbols = symbol_table.iter();
            let mut mangled_table = HashMap::<usize, Vec<RawString>>::new();

            while let Some(symbol) = symbols.next()? {
                match symbol.parse() {
                    Ok(pdb2::SymbolData::Public(data)) if data.function => {
                        let offset = data.offset.offset as usize;
                        mangled_table.entry(offset).or_default().push(data.name);
                    }
                    _ => {}
                }
            }
            mangled_table
        };

        //
        //
        //

        let dbi = leak(pdb.debug_information()?);
        let string_table: &'static pdb2::StringTable<'static> = leak(pdb.string_table()?);

        let mut modules = dbi.modules()?;

        while let Some(module) = modules.next()? {
            let Some(module_info) = pdb.module_info(&module)? else {
                continue;
            };
            let module_info = leak(module_info);

            let program = module_info.line_program()?;
            let mut iter = module_info.symbols()?;

            while let Some(symbol) = iter.next()? {
                let (name, offset, len) = match symbol.parse() {
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => (name, offset, len),
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        offset, len, name, ..
                    })) => (name, offset, len.into()),
                    _ => continue,
                };

                let function = Function::extract(
                    text_section_address,
                    text_data,
                    &program,
                    string_table,
                    &mangled_table,
                    name,
                    offset,
                    len,
                )?;

                this.functions
                    .entry(function.address)
                    .or_default()
                    .push(function);
            }
        }

        Ok(this)
    }

    fn build_object_files(self, ctx: &Capstone) -> anyhow::Result<ObjectFiles<'static>> {
        let mut object_files = ObjectFiles {
            objects: HashMap::new(),
        };

        for fun in self.functions.values().flatten() {
            const VOSTOK_PREFIX: &[u8] = b"c:\\survarium\\sources\\vostok";
            let filename: &'static [u8] = match fun.filename {
                Some(filename) => match filename.as_bytes().strip_prefix(VOSTOK_PREFIX) {
                    Some(filename) => filename,
                    None => continue,
                },
                // See [2]
                None => continue,
            };

            let object_file = object_files.objects.entry(filename).or_insert_with(|| {
                let mut object_file = object::write::Object::new(
                    object::BinaryFormat::Coff,
                    object::Architecture::I386,
                    object::Endianness::Little,
                );

                let _data_section_id =
                    object_file.add_section(vec![], b".data".into(), SectionKind::Data);
                let _rdata_section_id =
                    object_file.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData);
                let _text_section_id =
                    object_file.add_section(vec![], b".text".into(), SectionKind::Text);

                object_file
            });

            self.append_to_object_file(object_file, ctx, fun)?;
        }

        Ok(object_files)
    }

    fn append_to_object_file(
        &self,
        object_file: &mut object::write::Object,
        ctx: &Capstone,
        fun: &Function,
    ) -> anyhow::Result<()> {
        let mut data: Vec<u8> = Vec::new();
        let mut rdata: Vec<u8> = Vec::new();
        let mut text: Vec<u8> = Vec::new();

        let ixs = ctx.disasm_all(&fun.data, fun.address as u64)?;
        for ix in ixs.iter() {
            let detail = ctx.insn_detail(ix)?;
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

                let target_address = usize::try_from(target_address)?;

                let internal_branch =
                    (fun.address..fun.address + fun.data.len()).contains(&target_address);
                if !internal_branch {
                    let target_fun = self.functions.get(&target_address);

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

            // println!(
            //     "  {:#010x}: {} {}{}",
            //     ix.address(),
            //     ix.mnemonic().unwrap_or(""),
            //     ix.op_str().unwrap_or(""),
            //     match fn_name {
            //         None => format!(""),
            //         Some(fn_name) => format!(" | CALLING {fn_name}"),
            //     },
            // )
        }
        Ok(())
    }
}

impl Function<'static> {
    fn extract(
        text_section_address: usize,
        text_data: &'static [u8],

        program: &pdb2::LineProgram,
        string_table: &'static pdb2::StringTable<'static>,
        mangled_table: &std::collections::HashMap<usize, Vec<RawString<'static>>>,

        name: pdb2::RawString<'static>,
        offset: pdb2::PdbInternalSectionOffset,
        len: u32,
    ) -> anyhow::Result<Self> {
        let mut filename = None;

        let mut lines = program.lines_for_symbol(offset);
        while let Some(line_info) = lines.next()? {
            let file_info = program.get_file_info(line_info.file_index)?;
            filename = Some(string_table.get(file_info.name)?);
            // filename = Some(file_info.name.to_raw_string(&string_table)?);
            break;
        }

        let offset = offset.offset as usize;
        let len = len as usize;
        if len == 0 {
            anyhow::bail!("Functions cannot be unsized")
        }

        let mangled_name: Option<RawString> = match mangled_table.get(&offset) {
            Some(symbols) if symbols.len() == 1 => Some(symbols[0]),
            Some(symbols) => Some(find_closest_symbol(name, &symbols)),
            None => None,
        };

        Ok(Function {
            name,
            mangled_name: mangled_name,
            filename: filename,
            address: text_section_address + offset,
            data: &text_data[offset..offset + len],
        })
    }
}

// rfind + contains works for `&str`
// windows + rposition works for `&[u8]`
fn find_closest_symbol<'a, 'p>(name: RawString, symbols: &'a [RawString<'p>]) -> RawString<'p> {
    let pure_name = {
        let idx = name
            .as_bytes()
            .windows(2)
            .rposition(|w| w == b"::")
            .map(|i| i + 2)
            .unwrap_or(0);
        &name.as_bytes()[idx..]
    };
    let closest_symbol = symbols
        .iter()
        .filter(|symbol| {
            symbol
                .as_bytes()
                .windows(pure_name.len())
                .any(|w| w == pure_name)
        })
        .min_by_key(|symbol| symbol.len());
    if let Some(closest_symbol) = closest_symbol {
        return *closest_symbol;
    }
    *symbols
        .iter()
        .min_by_key(|symbol| symbol.len())
        .expect("Symbols might contain at least a single element")
}

// Most of those leaks have to exist to "leak" Streams which for some reason are owning in pdb crate.
fn leak<T>(object: T) -> &'static T {
    Box::leak(Box::new(object))
}

// [2]
//
// survarium::game_scene::~game_scene
// survarium::link_resolver::link_resolver
// survarium::rifle_scope::~rifle_scope
// survarium::simple_animation_controller_parameters::operator=
// vostok::ai::fsm_state::fsm_state
// vostok::ai::npc_statistics::npc_statistics
// vostok::ai::npc_statistics::~npc_statistics
// vostok::ai::planning::base_lexeme::`vcall'{12}'
// vostok::ai::planning::base_lexeme::`vcall'{4}'
// vostok::ai::planning::base_lexeme::`vcall'{8}'
// vostok::ai::statistics_item<46,16>::~statistics_item<46,16>
// vostok::animation::fermi_interpolator::~fermi_interpolator
// vostok::animation::instant_interpolator::~instant_interpolator
// vostok::animation::mixing::animation_interval::~animation_interval
// vostok::fs_new::physical_path_info_data::physical_path_info_data
// vostok::memory::stack_allocator::~stack_allocator
// vostok::particle::lod_entry::lod_entry
// vostok::render::environment_probe_properties::operator=
// vostok::render::functor_command::~functor_command
// vostok::render::sky_ambient_occlusion_properties::operator=
// vostok::render::sky_dome_geometry::~sky_dome_geometry
// vostok::render::sliced_cube_geometry::~sliced_cube_geometry
// vostok::render::sphere_geometry::~sphere_geometry
// vostok::render::stage_lights::lights_instance::lights_instance
// vostok::render::stage_view_mode::~stage_view_mode
// vostok::vfs::async_callbacks_data::~async_callbacks_data
// vostok::vfs::find_environment::find_environment
// vostok::vfs::query_mount_arguments::query_mount_arguments
// vostok::vfs::virtual_file_system::~virtual_file_system

// [3]
//
// "vostok::render::static_render_model_instance::static_render_model_instance",
// "btCollisionWorld::RayResultCallback::getShapeId",
// "vostok::collision::object::object",
// "vostok::network_core::buffer_to_send",
// "vostok::animation::bone_names::create_internals_in_place",
// "vostok::collision::box_geometry_instance",
// "vostok::",
// "survarium::",

// [4]
//
// # Static function in namespace
//
// vostok::render::get_world_to_decal_matrix
// <NO MANGLED NAME>
// c:\survarium\sources\vostok\render\engine\sources\decal_instance.cpp
//
//
// # Static function without namespace
//
// free_region_impl
// <NO MANGLED NAME>
// c:\survarium\sources\vostok\core\sources\memory_win.cpp
//
//
// # Compiler generate function in namespace
//
// vostok::animation::`dynamic atexit destructor for 's_bi_spline_skeleton_animation_impl_cook''
// <NO MANGLED NAME>
// c:\survarium\sources\vostok\animation\sources\bi_spline_skeleton_animation_impl_cook.cpp

// [5]
//
// {
//     let fun_name = fun.name.to_string();
//
//     let fun_mangled_name = fun.mangled_name.map(|name| name.to_string());
//     let fun_mangled_name = fun_mangled_name.as_deref().unwrap_or("<NO MANGLED NAME>");
//
//     let fun_filename = fun.filename.map(|name| name.to_string());
//     let fun_filename = fun_filename.as_deref().unwrap_or("<NO FILNAME>");
//
//     println!(
//         "\n{fun_name}\n{fun_mangled_name}\n{fun_filename}\n{:#010x} {:#010x} ",
//         fun.address,
//         fun.address + fun.data.len()
//     );
// }
