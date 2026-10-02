use crate::Env;
use crate::pdb_symbols::PdbSymbols;
use crate::relocs;
use crate::utils::{ToUsize, leak};

use object::{Object, ObjectSection};
use pdb2::FallibleIterator;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const HEADER: &str = "site_rva\tsource_section\ttarget_rva\ttarget_section\t\
source_module\tsource_archive\tsource_contribution_rva\tsource_contribution_size\t\
target_module\ttarget_archive\ttarget_contribution_rva\ttarget_contribution_size\t\
reason\n";

/// Every address the PDB names: public and data symbols, procedures, thunks
/// and code labels.
struct PdbIndex {
    symbol_starts: BTreeSet<usize>,
    modules: Vec<(String, String)>,
}

impl PdbIndex {
    fn parse<S>(env: &Env, pdb: &mut pdb2::PDB<'static, S>) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let rva = |offset: pdb2::PdbInternalSectionOffset| {
            [env.text, env.rdata, env.data]
                .into_iter()
                .find(|section| section.id == offset.section)
                .map(|section| section.rva + offset.offset.to_usize())
        };
        let mut symbol_starts = BTreeSet::new();
        let mut globals = env.symbol_table.iter();
        while let Some(symbol) = globals.next()? {
            let offset = match symbol.parse()? {
                pdb2::SymbolData::Public(pdb2::PublicSymbol { offset, .. })
                | pdb2::SymbolData::Data(pdb2::DataSymbol { offset, .. }) => offset,
                _ => continue,
            };
            symbol_starts.extend(rva(offset));
        }

        let mut modules = Vec::new();
        let mut module_iter = env.dbi.modules()?;
        while let Some(module) = module_iter.next()? {
            modules.push((
                module.module_name().into_owned(),
                module.object_file_name().into_owned(),
            ));
            let Some(module_info) = pdb.module_info(&module)? else {
                continue;
            };
            let module_info = leak(module_info);
            let mut symbols = module_info.symbols()?;
            while let Some(symbol) = symbols.next()? {
                let offset = match symbol.parse() {
                    Ok(pdb2::SymbolData::Procedure(pdb2::ProcedureSymbol { offset, .. }))
                    | Ok(pdb2::SymbolData::Thunk(pdb2::ThunkSymbol { offset, .. }))
                    | Ok(pdb2::SymbolData::Label(pdb2::LabelSymbol { offset, .. }))
                        if offset.section == env.text.id =>
                    {
                        offset
                    }
                    Ok(pdb2::SymbolData::Data(pdb2::DataSymbol { offset, .. }))
                        if offset.section != env.text.id =>
                    {
                        offset
                    }
                    _ => continue,
                };
                symbol_starts.extend(rva(offset));
            }
        }
        Ok(Self {
            symbol_starts,
            modules,
        })
    }
}

/// Write the HIGHLOW relocation referents in `.text`, `.rdata` and `.data`
/// that no PDB symbol names or contains, with the compiland contributions of
/// their site and target.
pub fn write<S>(
    env: &Env,
    exe: &'static object::read::pe::PeFile32<'static>,
    pdb: &mut pdb2::PDB<'static, S>,
    symbols: &PdbSymbols,
    path: &Path,
) -> anyhow::Result<()>
where
    S: pdb2::Source<'static> + 'static,
{
    let Some(sites) = relocs::retained_highlow_sites(exe)? else {
        anyhow::bail!("--write-missing-data-index needs a PE base relocation directory");
    };
    let index = PdbIndex::parse(env, pdb)?;
    let mut contributions = Vec::new();
    let mut contribution_iter = env.dbi.section_contributions()?;
    while let Some(contribution) = contribution_iter.next()? {
        contributions.push(contribution);
    }

    let mut rows = Vec::new();
    let mut relevant = 0usize;
    for site_rva in sites {
        let Some(raw_value) = u32_at(exe, env.image_base.to_usize(), site_rva) else {
            continue;
        };
        let target_rva = raw_value.wrapping_sub(env.image_base).to_usize();
        let Some(target_section) = target_section_at(env, target_rva) else {
            continue;
        };
        relevant += 1;
        if pdb_owns(symbols, &index, target_section, target_rva) {
            continue;
        }
        let source_section =
            source_section_at(exe, env.image_base.to_usize(), site_rva).unwrap_or("outside");
        rows.push((
            site_rva,
            source_section.to_owned(),
            target_rva,
            target_section,
            contribution_owner(env, &index, &contributions, site_rva),
            contribution_owner(env, &index, &contributions, target_rva),
        ));
    }
    rows.sort_unstable_by_key(|row| (row.0, row.2));

    let mut output = String::with_capacity(rows.len() * 72);
    writeln!(output, "# relevant_xrefs={relevant}")?;
    writeln!(output, "# pdb_owned_xrefs={}", relevant - rows.len())?;
    output.push_str(HEADER);
    for (site, source, target, section, source_owner, target_owner) in &rows {
        let (source_module, source_archive, source_start, source_size) = source_owner;
        let (target_module, target_archive, target_start, target_size) = target_owner;
        writeln!(
            output,
            "{site:#x}\t{source}\t{target:#x}\t{section}\t{source_module}\t\
             {source_archive}\t{source_start:#x}\t{source_size:#x}\t\
             {target_module}\t{target_archive}\t{target_start:#x}\t\
             {target_size:#x}\tno exact or extent-backed PDB symbol",
        )?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, output)?;
    eprintln!(
        "[missing-data-index] {} of {} relevant HIGHLOW referents lack a PDB owner -> {}",
        rows.len(),
        relevant,
        path.display()
    );
    Ok(())
}

fn contribution_owner(
    env: &Env,
    index: &PdbIndex,
    contributions: &[pdb2::DBISectionContribution],
    target_rva: usize,
) -> (String, String, usize, usize) {
    let section_offset = [env.text, env.rdata, env.data]
        .into_iter()
        .find_map(|section| {
            contains(section, target_rva, 1).then_some((
                section.id,
                target_rva - section.rva,
                section.rva,
            ))
        });
    let Some((section_id, offset, section_rva)) = section_offset else {
        return ("-".to_owned(), "-".to_owned(), 0, 0);
    };
    let owner = contributions
        .iter()
        .filter(|contribution| {
            contribution.offset.section == section_id
                && contribution.offset.offset.to_usize() <= offset
                && offset < contribution.offset.offset.to_usize() + contribution.size.to_usize()
        })
        .min_by_key(|contribution| contribution.size);
    owner
        .map(|contribution| {
            let (module, archive) = index
                .modules
                .get(contribution.module)
                .map(|(module, archive)| (clean_field(module), clean_field(archive)))
                .unwrap_or_else(|| ("-".to_owned(), "-".to_owned()));
            (
                module,
                archive,
                section_rva + contribution.offset.offset.to_usize(),
                contribution.size.to_usize(),
            )
        })
        .unwrap_or_else(|| ("-".to_owned(), "-".to_owned(), 0, 0))
}

fn clean_field(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

/// Whether a PDB symbol starts at `target_rva`, or a function or string
/// literal of known extent contains it. Data symbols own only their start.
fn pdb_owns(symbols: &PdbSymbols, index: &PdbIndex, section: &str, target_rva: usize) -> bool {
    if index.symbol_starts.contains(&target_rva) {
        return true;
    }
    match section {
        ".text" => symbols
            .functions
            .range(..=target_rva)
            .next_back()
            .and_then(|(rva, _)| Some((rva, symbols.function_extent(*rva)?)))
            .is_some_and(|(rva, size)| target_rva - rva < size),
        ".rdata" => symbols
            .strings
            .range(..=target_rva)
            .next_back()
            .is_some_and(|(rva, (_, data))| target_rva - rva < data.len()),
        _ => false,
    }
}

fn target_section_at(env: &Env, rva: usize) -> Option<&'static str> {
    if contains(env.text, rva, 1) {
        return Some(".text");
    }
    if contains(env.rdata, rva, 1) {
        return Some(".rdata");
    }
    if contains(env.data, rva, 1) {
        return Some(if rva - env.data.rva < env.data.data.len() {
            ".data"
        } else {
            ".bss"
        });
    }
    None
}

fn contains(section: crate::SecInfo<'_>, rva: usize, size: usize) -> bool {
    section.size != 0 && section.rva <= rva && rva + size <= section.rva + section.size
}

fn source_section_at<'a>(
    exe: &'a object::read::pe::PeFile32<'_>,
    image_base: usize,
    rva: usize,
) -> Option<&'a str> {
    exe.sections().find_map(|section| {
        let start = section.address().to_usize().checked_sub(image_base)?;
        let size = section.size().to_usize();
        (start <= rva && rva < start + size)
            .then(|| section.name().ok())
            .flatten()
    })
}

fn u32_at(exe: &object::read::pe::PeFile32<'_>, image_base: usize, rva: usize) -> Option<u32> {
    for section in exe.sections() {
        let start = section.address().to_usize().checked_sub(image_base)?;
        let size = section.size().to_usize();
        if start <= rva && rva + 4 <= start + size {
            let offset = rva - start;
            let data = section.data().ok()?;
            let bytes = data.get(offset..offset + 4)?;
            return Some(u32::from_le_bytes(bytes.try_into().ok()?));
        }
    }
    None
}
