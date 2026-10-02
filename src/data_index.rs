use crate::Env;
use crate::pdb_symbols::TypeSizeResolver;
use crate::utils::ToUsize;

use pdb2::{FallibleIterator, TypeIndex};

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

const HEADER: &str = "rva\tsection\tstorage\tsize\tsize_kind\ttype_index\tscope\tmodule_hex\tarchive_hex\tname_hex\tpublic_name_hex\n";

#[derive(Clone, Debug)]
struct Row {
    rva: usize,
    section: &'static str,
    storage: &'static str,
    size: Option<usize>,
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
    let mut type_sizes = TypeSizeResolver::parse(pdb);

    let mut rows = Vec::new();
    let mut public_names: BTreeMap<usize, (Vec<u8>, &'static str, &'static str)> = BTreeMap::new();
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
                        size: type_sizes.size_of(data.type_index),
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
                size: type_sizes.size_of(data.type_index),
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

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}
