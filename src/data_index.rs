use crate::Env;
use crate::utils::ToUsize;

use pdb2::{FallibleIterator, RawString, TypeData, TypeIndex};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

const HEADER: &str = "rva\tsection\tstorage\tsize\tsize_kind\ttype_index\tscope\tmodule_hex\tarchive_hex\tname_hex\tpublic_name_hex\n";

#[derive(Clone, Debug)]
struct Row {
    rva: usize,
    section: &'static str,
    storage: &'static str,
    size: Option<u64>,
    type_index: TypeIndex,
    scope: &'static str,
    module: Vec<u8>,
    archive: Vec<u8>,
    name: Vec<u8>,
    public_name: Vec<u8>,
}

pub fn write<S>(env: &Env, pdb: &mut pdb2::PDB<'static, S>, path: &Path) -> anyhow::Result<()>
where
    S: pdb2::Source<'static> + 'static,
{
    let type_information = pdb.type_information()?;
    let mut type_finder = type_information.finder();
    let mut complete_sizes = HashMap::new();
    let mut type_iter = type_information.iter();
    while let Some(typ) = type_iter.next()? {
        type_finder.update(&type_iter);
        match typ.parse() {
            Ok(TypeData::Class(data)) if !data.properties.forward_reference() => {
                remember_complete_size(&mut complete_sizes, data.name, data.unique_name, data.size);
            }
            Ok(TypeData::Union(data)) if !data.properties.forward_reference() => {
                remember_complete_size(&mut complete_sizes, data.name, data.unique_name, data.size);
            }
            _ => {}
        }
    }

    let mut rows = Vec::new();
    let mut public_names: BTreeMap<usize, (Vec<u8>, &'static str, &'static str)> =
        BTreeMap::new();
    let mut globals = env.symbol_table.iter();
    while let Some(symbol) = globals.next()? {
        match symbol.parse()? {
            pdb2::SymbolData::Public(data) if !data.function => {
                if let Some((rva, section, storage)) = data_location(env, data.offset) {
                    public_names
                        .entry(rva)
                        .or_insert_with(|| (data.name.as_bytes().to_vec(), section, storage));
                }
            }
            pdb2::SymbolData::Data(data) => {
                if let Some((rva, section, storage)) = data_location(env, data.offset) {
                    rows.push(Row {
                        rva,
                        section,
                        storage,
                        size: type_size(&type_finder, data.type_index, &complete_sizes, 0),
                        type_index: data.type_index,
                        scope: if data.global { "external" } else { "local" },
                        module: Vec::new(),
                        archive: Vec::new(),
                        name: data.name.as_bytes().to_vec(),
                        public_name: Vec::new(),
                    });
                }
            }
            _ => {}
        }
    }

    let mut modules = env.dbi.modules()?;
    while let Some(module) = modules.next()? {
        let module_name = module.module_name().as_bytes().to_vec();
        let archive_name = module.object_file_name().as_bytes().to_vec();
        let Some(module_info) = pdb.module_info(&module)? else {
            continue;
        };
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            let Ok(pdb2::SymbolData::Data(data)) = symbol.parse() else {
                continue;
            };
            let Some((rva, section, storage)) = data_location(env, data.offset) else {
                continue;
            };
            rows.push(Row {
                rva,
                section,
                storage,
                size: type_size(&type_finder, data.type_index, &complete_sizes, 0),
                type_index: data.type_index,
                scope: if data.global { "external" } else { "local" },
                module: module_name.clone(),
                archive: archive_name.clone(),
                name: data.name.as_bytes().to_vec(),
                public_name: Vec::new(),
            });
        }
    }

    let represented_rvas: HashSet<usize> = rows.iter().map(|row| row.rva).collect();
    for (rva, (name, section, storage)) in &public_names {
        if represented_rvas.contains(rva) {
            continue;
        }
        rows.push(Row {
            rva: *rva,
            section,
            storage,
            size: None,
            type_index: TypeIndex(0),
            scope: "external",
            module: Vec::new(),
            archive: Vec::new(),
            name: name.clone(),
            public_name: name.clone(),
        });
    }

    let owned: HashSet<(usize, Vec<u8>)> = rows
        .iter()
        .filter(|row| !row.module.is_empty())
        .map(|row| (row.rva, row.name.clone()))
        .collect();
    rows.retain(|row| !row.module.is_empty() || !owned.contains(&(row.rva, row.name.clone())));
    for row in &mut rows {
        if let Some((name, _, _)) = public_names.get(&row.rva) {
            row.public_name.clone_from(name);
        }
    }
    rows.sort_unstable_by(|left, right| {
        (left.rva, &left.module, &left.name).cmp(&(right.rva, &right.module, &right.name))
    });
    rows.dedup_by(|left, right| {
        left.rva == right.rva && left.module == right.module && left.name == right.name
    });

    let mut output = String::with_capacity(rows.len() * 160);
    output.push_str(HEADER);
    for row in &rows {
        let size = row
            .size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            output,
            "{:#x}\t{}\t{}\t{}\t{}\t{:#x}\t{}\t{}\t{}\t{}\t{}",
            row.rva,
            row.section,
            row.storage,
            size,
            if row.size.is_some() {
                "pdb-type"
            } else {
                "unknown"
            },
            row.type_index.0,
            row.scope,
            hex(&row.module),
            hex(&row.archive),
            hex(&row.name),
            hex(&row.public_name),
        )?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, output)?;
    eprintln!(
        "[data-index] wrote {} PDB data records -> {}",
        rows.len(),
        path.display()
    );
    Ok(())
}

fn remember_complete_size(
    sizes: &mut HashMap<Vec<u8>, u64>,
    name: RawString<'_>,
    unique_name: Option<RawString<'_>>,
    size: u64,
) {
    if size == 0 {
        return;
    }
    sizes.insert(name.as_bytes().to_vec(), size);
    if let Some(name) = unique_name {
        sizes.insert(name.as_bytes().to_vec(), size);
    }
}

fn data_location(
    env: &Env,
    offset: pdb2::PdbInternalSectionOffset,
) -> Option<(usize, &'static str, &'static str)> {
    if offset.section == env.rdata.id {
        let rva = env.rdata.rva + offset.offset.to_usize();
        return Some((rva, ".rdata", "rdata"));
    }
    if offset.section == env.data.id {
        let rva = env.data.rva + offset.offset.to_usize();
        let storage = if offset.offset.to_usize() < env.data.data.len() {
            "data"
        } else {
            "bss"
        };
        return Some((rva, ".data", storage));
    }
    None
}

fn type_size(
    finder: &pdb2::TypeFinder<'_>,
    index: TypeIndex,
    complete_sizes: &HashMap<Vec<u8>, u64>,
    depth: usize,
) -> Option<u64> {
    if depth > 32 {
        return None;
    }
    match finder.find(index).ok()?.parse().ok()? {
        TypeData::Primitive(data) => primitive_size(data),
        TypeData::Class(data) => {
            if data.size != 0 {
                Some(data.size)
            } else {
                data.unique_name
                    .and_then(|name| complete_sizes.get(name.as_bytes()).copied())
                    .or_else(|| complete_sizes.get(data.name.as_bytes()).copied())
            }
        }
        TypeData::Union(data) => {
            if data.size != 0 {
                Some(data.size)
            } else {
                data.unique_name
                    .and_then(|name| complete_sizes.get(name.as_bytes()).copied())
                    .or_else(|| complete_sizes.get(data.name.as_bytes()).copied())
            }
        }
        TypeData::Array(data) => data.dimensions.last().map(|size| u64::from(*size)),
        TypeData::Pointer(data) => {
            Some(u64::from(data.attributes.size())).filter(|size| *size != 0)
        }
        TypeData::Modifier(data) => {
            type_size(finder, data.underlying_type, complete_sizes, depth + 1)
        }
        TypeData::Enumeration(data) => {
            type_size(finder, data.underlying_type, complete_sizes, depth + 1)
        }
        TypeData::Alias(data) => type_size(finder, data.underlying_type, complete_sizes, depth + 1),
        TypeData::Bitfield(data) => {
            type_size(finder, data.underlying_type, complete_sizes, depth + 1)
        }
        _ => None,
    }
}

fn primitive_size(data: pdb2::PrimitiveType) -> Option<u64> {
    if let Some(indirection) = data.indirection {
        return match indirection {
            pdb2::Indirection::Near16 => Some(2),
            pdb2::Indirection::Far16 | pdb2::Indirection::Huge16 => Some(4),
            pdb2::Indirection::Near32 => Some(4),
            pdb2::Indirection::Far32 => Some(6),
            pdb2::Indirection::Near64 => Some(8),
            pdb2::Indirection::Near128 => Some(16),
        };
    }
    use pdb2::PrimitiveKind::*;
    match data.kind {
        Char | UChar | RChar | Char8 | I8 | U8 | Bool8 => Some(1),
        WChar | RChar16 | Short | UShort | I16 | U16 | F16 | Bool16 => Some(2),
        RChar32 | Long | ULong | I32 | U32 | F32 | F32PP | Bool32 | HRESULT => Some(4),
        F48 => Some(6),
        Quad | UQuad | I64 | U64 | F64 | Complex32 | Bool64 => Some(8),
        F80 => Some(10),
        Octa | UOcta | I128 | U128 | F128 | Complex64 => Some(16),
        Complex80 => Some(20),
        Complex128 => Some(32),
        NoType | Void => None,
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}
