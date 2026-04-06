use crate::pdb_symbols::PdbSymbols;
use crate::relocs::RelocKind;
use crate::utils::{contains, leak, ToU64, ToUsize};
use crate::Env;

use std::collections::{BTreeMap, HashMap};

use capstone::arch::x86::{ArchMode, ArchSyntax, X86Operand, X86OperandType};
use capstone::arch::ArchOperand;
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::Capstone;
use capstone::InsnGroupType::*;

use pdb2::{FallibleIterator, RawString};

use object::SectionKind;

pub struct ObjectFiles<'a> {
    pub objects: HashMap<&'a [u8], ObjectFile>,
}

pub struct ObjectFile {
    pub object: object::write::Object<'static>,
    // @TODO: Values of initialized statics will be here.
    pub _data_section_id: object::write::SectionId,
    pub rdata_section_id: object::write::SectionId,
    pub text_section_id: object::write::SectionId,
}

#[derive(Copy, Clone)]
pub struct ObjectOffset {
    offset: u64,
    section_id: object::write::SectionId,
}

#[derive(Copy, Clone)]
pub enum ObjectLocation {
    Offset(ObjectOffset),
    Extern,
}

impl ObjectFiles<'_> {
    pub fn parse<'s, S>(
        env: &Env,
        pdb: &mut pdb2::PDB<'static, S>,

        symbols: &'s PdbSymbols,
        coff_data: &[u8],
        mut relocs_rva: BTreeMap<usize, RelocKind<'s>>,

        engine_path: &[u8],
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let mut this = Self {
            objects: HashMap::new(),
        };

        let ctx = Capstone::new()
            .x86()
            .mode(ArchMode::Mode32)
            .syntax(ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Cannot create Capstone context");

        let mut modules = env.dbi.modules()?;
        while let Some(module) = modules.next()? {
            let Some(module_info) = pdb.module_info(&module)? else {
                continue;
            };
            let module_info = leak(module_info);

            let program = module_info.line_program()?;
            let mut iter = module_info.symbols()?;

            while let Some(symbol) = iter.next()? {
                let (fun_name, fun_offset, fun_size) = match symbol.parse() {
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol {
                        name,
                        offset,
                        len,
                        ..
                    })) => (name, offset, len.to_usize()),
                    Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol {
                        name, offset, len, ..
                    })) => (name, offset, len.to_usize()),
                    _ => continue,
                };

                let Some(filename) = get_function_location(
                    &program,
                    env.string_table,
                    fun_name,
                    fun_offset,
                    engine_path,
                )?
                else {
                    continue;
                };

                let fun_rva = env.text.rva + fun_offset.offset.to_usize();
                let fun_bytes = resolve_relative_relocations(
                    env,
                    &ctx,
                    fun_rva,
                    fun_size,
                    symbols,
                    coff_data,
                    &mut relocs_rva,
                )?;

                let object_file = this
                    .objects
                    .entry(filename)
                    .or_insert_with(|| ObjectFile::empty(engine_path));

                let fun_name = match symbols.functions.get(&fun_rva) {
                    Some(overloads) => find_closest_symbol_name(&fun_name, overloads),
                    _ => fun_name,
                };

                let fun_offset_in_coff_text = object_file.add_function(fun_name, &fun_bytes);

                for (reloc_rva, reloc_kind) in relocs_rva.range(fun_rva..fun_rva + fun_size) {
                    let reloc_rva = *reloc_rva;
                    let reloc_kind = *reloc_kind;

                    let reloc_offset_in_fun = reloc_rva - fun_rva;
                    let reloc_offset_in_coff_text = fun_offset_in_coff_text + reloc_offset_in_fun;

                    object_file.add_relocation_at(
                        reloc_kind,
                        reloc_offset_in_coff_text,
                        fun_name,
                        &relocs_rva,
                    )?;
                }
            }
        }

        Ok(this)
    }

    pub fn write(self, base: &std::path::Path) -> anyhow::Result<()> {
        let base_len = base.as_os_str().as_encoded_bytes().len();
        let mut path = base.to_path_buf();

        for (prefix, object_file) in self.objects {
            path.as_mut_os_string().truncate(base_len);

            let prefix = prefix
                .iter()
                .map(|&c| match c {
                    b'\\' => '/',
                    _ => char::from(c),
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

impl ObjectFile {
    fn empty(engine_path: &[u8]) -> Self {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Coff,
            object::Architecture::I386,
            object::Endianness::Little,
        );
        object.set_mangling(object::write::Mangling::None);

        let data_section_id = object.add_section(vec![], b".data".into(), SectionKind::Data);
        let rdata_section_id =
            object.add_section(vec![], b".rdata".into(), SectionKind::ReadOnlyData);
        let text_section_id = object.add_section(vec![], b".text".into(), SectionKind::Text);

        // objdiff considers allocations to match if name is equal OR(!) offset
        // into reloc table is the same.
        //
        // This makes different relocations with different data and different names
        // to match, if they offsets match. These 4 bytes prevent that.
        if engine_path == b"c:\\survarium\\sources\\" {
            object.append_section_data(rdata_section_id, &0_u32.to_le_bytes(), 4);
        }

        Self {
            object,
            _data_section_id: data_section_id,
            rdata_section_id,
            text_section_id,
        }
    }
}

/// Returns object file location for a given function.
//
// @NOTE: This function will leak memory in some cases.
// This simplifies string passing, and shouldn't matter for this script.
fn get_function_location(
    program: &pdb2::LineProgram<'static>,
    string_table: &'static pdb2::StringTable<'static>,

    fun_name: RawString<'static>,
    fun_offset: pdb2::PdbInternalSectionOffset,

    engine_path: &[u8],
) -> anyhow::Result<Option<&'static [u8]>> {
    let mut filename = None;

    let mut lines = program.lines_for_symbol(fun_offset);
    // Extracting only a single line should be enough to find a source file.
    if let Some(line_info) = lines.next()? {
        let file_info = program.get_file_info(line_info.file_index)?;
        filename = Some(string_table.get(file_info.name)?);
    }

    let location: &'static [u8] = match filename {
        Some(filename) => match filename.as_bytes().strip_prefix(engine_path) {
            Some(filename) => filename,
            None => return Ok(None),
        },
        None => match fun_name.as_bytes() {
            name if !contains(name, b"::") && !name.contains(&b' ') => b"_msvc_internal\\c_lang",
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

    Ok(Some(location))
}

/// Resolve external relative jumps in the function as relocations.
///
/// And return the final resolved function assembly.
// @NOTE: There is no reason to grow `relocs_rva`, since these allocations
// are specific to the current function and don't need to be kept alive after
// the function is processed.
//
// At the same time `relocs_rva` sorts automatically!
fn resolve_relative_relocations<'s>(
    env: &Env,
    ctx: &Capstone,

    fun_rva: usize,
    fun_size: usize,

    symbols: &'s PdbSymbols,

    coff_data: &[u8],
    relocs_rva: &mut BTreeMap<usize, RelocKind<'s>>,
) -> anyhow::Result<Vec<u8>> {
    let fun_va = env.image_base.to_usize() + fun_rva;

    // @NOTE: Requires a new allocation, since capstone cannot borrow function code mutably.
    let mut fun_bytes = coff_data[fun_rva..fun_rva + fun_size].to_vec();
    let mut offset_in_fun = 0;

    let ixs = ctx.disasm_all(&coff_data[fun_rva..fun_rva + fun_size], fun_va.to_u64())?;
    for ix in ixs.iter() {
        offset_in_fun += ix.len();

        let detail = ctx.insn_detail(ix)?;
        let arch_detail = detail.arch_detail();

        let groups = detail.groups().iter().map(|v| u32::from(v.0));

        let is_branch = groups.clone().any(|v| v == CS_GRP_BRANCH_RELATIVE);

        if !is_branch {
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

        let target_va = u64::try_from(target_va)?;
        let target_rva = target_va - u64::from(env.image_base);

        let internal_branch = (fun_rva..fun_rva + fun_size).contains(&(target_rva.to_usize()));
        if internal_branch {
            continue;
        }

        if ix.len() <= 4 {
            // Read data as code. Which is jump tables stored inline.
            continue;
        }

        let Some(overloads) = symbols.functions.get(&target_rva.to_usize()) else {
            // Read data as code. Which is jump tables stored inline.
            continue;
        };

        // if fun_name == b"" {

        // }

        let overloads = overloads.as_slice();

        fun_bytes[offset_in_fun - 4..offset_in_fun].copy_from_slice(&0_u32.to_le_bytes());
        let old_reloc = relocs_rva.insert(
            fun_rva + offset_in_fun - 4,
            RelocKind::Function { overloads },
        );

        if let Some(old_reloc) = old_reloc {
            let RelocKind::Function {
                overloads: old_overloads,
            } = old_reloc
            else {
                unreachable!();
            };
            assert_eq!(overloads.as_ptr(), old_overloads.as_ptr());
        }
    }

    Ok(fun_bytes)
}

impl ObjectFile {
    fn add_relocation_at(
        &mut self,
        reloc_kind: RelocKind,
        reloc_offset: ObjectOffset,
        //
        fun_name: RawString,
        relocs_rva: &BTreeMap<usize, RelocKind>,
    ) -> anyhow::Result<()> {
        let reloc_name = reloc_kind.get_name(fun_name, relocs_rva);
        let reloc_name = reloc_name.as_raw_string();

        match reloc_kind {
            RelocKind::Function { overloads: _ } => {
                self.add_relocation(reloc_name, ObjectLocation::Extern, reloc_offset)?;
            }

            RelocKind::ConstantString { symbol: _, data } => {
                let const_offset_in_coff_rdata =
                    self.append_section_data(self.rdata_section_id, data, 0x00);

                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                )?;
            }

            RelocKind::ConstantValue {
                target_data,
                maybe_rva,
            } => {
                let const_offset_in_coff_rdata = self.append_section_data(
                    self.rdata_section_id,
                    &target_data.to_le_bytes(),
                    0x00,
                );
                self.add_relocation(
                    reloc_name,
                    ObjectLocation::Offset(const_offset_in_coff_rdata),
                    reloc_offset,
                )?;

                match maybe_rva.and_then(|rva| relocs_rva.get(&rva)) {
                    Some(chained_reloc_kind) => {
                        self.add_relocation_at(
                            *chained_reloc_kind,
                            const_offset_in_coff_rdata,
                            fun_name,
                            relocs_rva,
                        )?;
                    }
                    None => (),
                }
            }

            RelocKind::Static { symbol: _ } => {
                self.add_relocation(reloc_name, ObjectLocation::Extern, reloc_offset)?;
            }
        }

        Ok(())
    }
}

impl ObjectFile {
    fn append_section_data(
        &mut self,
        section_id: object::write::SectionId,
        data: &[u8],
        pad: u8,
    ) -> ObjectOffset {
        let offset = append_with_padding(&mut self.object, section_id, data, pad);
        ObjectOffset { offset, section_id }
    }

    fn add_relocation(
        &mut self,
        name: RawString,
        location: ObjectLocation,
        offset: ObjectOffset,
    ) -> anyhow::Result<()> {
        let (value, kind, section) = match location {
            ObjectLocation::Extern => (
                0,
                object::SymbolKind::Unknown,
                object::write::SymbolSection::Undefined,
            ),
            ObjectLocation::Offset(ObjectOffset { offset, section_id }) => {
                let kind = if section_id == self.text_section_id {
                    object::SymbolKind::Text
                } else {
                    object::SymbolKind::Data
                };
                (
                    offset,
                    kind,
                    object::write::SymbolSection::Section(section_id),
                )
            }
        };

        let symbol = self.object.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size: u64::MAX,
            kind,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section,
            flags: object::SymbolFlags::None,
        });

        self.object.add_relocation(
            offset.section_id,
            object::write::Relocation {
                offset: offset.offset,
                symbol,
                addend: -4,
                flags: object::RelocationFlags::Generic {
                    kind: object::RelocationKind::Relative,
                    encoding: object::RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )?;

        Ok(())
    }

    fn add_function(&mut self, name: RawString, body: &[u8]) -> ObjectOffset {
        let fun_offset_in_coff_text = self.append_section_data(self.text_section_id, body, 0x90);

        self.object.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: fun_offset_in_coff_text.offset,
            size: u64::MAX,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(fun_offset_in_coff_text.section_id),
            flags: object::SymbolFlags::None,
        });

        fun_offset_in_coff_text
    }
}

// Parse PDB symbols by iterating through symbol table and then through all modules

enum Name<'a> {
    Borrowed(RawString<'a>),
    Owned(Vec<u8>),
}

impl<'a> RelocKind<'a> {
    fn get_name(
        self,

        fun_name: RawString<'a>,
        relocs_rva: &BTreeMap<usize, RelocKind<'a>>,
    ) -> Name<'a> {
        match self {
            Self::Function { overloads } => {
                Name::Borrowed(find_closest_relative_call(fun_name, overloads))
            }
            Self::ConstantString { symbol, data } => {
                let reloc_name = get_constant_name(symbol, data);
                Name::Owned(reloc_name)
            }
            Self::ConstantValue {
                target_data,
                maybe_rva,
            } => match maybe_rva.and_then(|rva| relocs_rva.get(&rva)) {
                None => {
                    let reloc_name = format!("value_0x{:x?}", target_data);
                    Name::Owned(reloc_name.into_bytes())
                }

                Some(chained_reloc_kind) => {
                    let mut chained_reloc_name = chained_reloc_kind.get_name(fun_name, relocs_rva);
                    chained_reloc_name.prepend(b"ptr_");
                    chained_reloc_name
                }
            },
            Self::Static { symbol: reloc_name } => Name::Borrowed(reloc_name),
        }
    }
}

impl Name<'_> {
    fn prepend(&mut self, prefix: &[u8]) {
        match self {
            Self::Owned(name) => _ = name.splice(0..0, prefix.iter().copied()),
            Self::Borrowed(name) => {
                *self = Self::Owned(name.as_bytes().to_vec());
                self.prepend(prefix);
            }
        }
    }

    fn as_raw_string(&self) -> RawString<'_> {
        match self {
            Self::Owned(name) => RawString::from(name.as_slice()),
            Self::Borrowed(name) => *name,
        }
    }
}

impl std::ops::Add<usize> for ObjectOffset {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Self {
            offset: self.offset + rhs.to_u64(),
            section_id: self.section_id,
        }
    }
}

// Always pads to 4
fn append_with_padding(
    object: &mut object::write::Object,
    section_id: object::write::SectionId,
    data: &[u8],
    pad: u8,
) -> u64 {
    let offset = object.append_section_data(section_id, data, 1);

    // sushi@NOTE: `object` crate doesn't(?) allow specifying auxiliary symbols.
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
    fun_name: RawString,
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

fn get_constant_name(symbol: RawString, data: &[u8]) -> Vec<u8> {
    match () {
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
            .map(|c| match c[0] == b'0' && c[1].is_ascii_alphanumeric() {
                true => c[1],
                false => b'_',
            })
            .collect::<Vec<_>>(),
        () => unreachable!(),
    }
}
