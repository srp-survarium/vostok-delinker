use crate::Env;
use crate::pdb_symbols::PdbSymbols;
use crate::utils::ToUsize;

use object::{Object, ObjectSection};
use pdb2::FallibleIterator;

use std::fmt::Write as _;
use std::path::Path;

const HEADER: &str = "site_rva\tsource_section\ttarget_rva\ttarget_section\t\
source_module\tsource_archive\tsource_contribution_rva\tsource_contribution_size\t\
target_module\ttarget_archive\ttarget_contribution_rva\ttarget_contribution_size\t\
reason\n";

#[repr(C)]
#[derive(bytemuck::AnyBitPattern, bytemuck::NoUninit, Copy, Clone)]
struct RelocHeader {
    page_rva: u32,
    block_size: u32,
}

#[repr(C)]
#[derive(bytemuck::AnyBitPattern, bytemuck::NoUninit, Copy, Clone)]
struct RelocEntry {
    entry: u16,
}

pub fn write(
    env: &Env,
    exe: &object::read::pe::PeFile32<'_>,
    symbols: &PdbSymbols,
    path: &Path,
) -> anyhow::Result<()> {
    let Some(reloc_sec) = exe.section_by_name(".reloc") else {
        anyhow::bail!("Missing .reloc section");
    };
    let reloc_data = reloc_sec.data()?;
    let mut contributions = Vec::new();
    let mut contribution_iter = env.dbi.section_contributions()?;
    while let Some(contribution) = contribution_iter.next()? {
        contributions.push(contribution);
    }
    let mut rows = Vec::new();
    let mut relevant = 0usize;
    let mut pos = 0;
    while pos + std::mem::size_of::<RelocHeader>() <= reloc_data.len() {
        let header_size = std::mem::size_of::<RelocHeader>();
        let RelocHeader {
            page_rva,
            block_size,
        } = bytemuck::pod_read_unaligned(&reloc_data[pos..pos + header_size]);
        if block_size < 8 || block_size == 0 {
            break;
        }
        let block_end = pos + block_size.to_usize();
        if block_end > reloc_data.len() {
            anyhow::bail!("truncated .reloc block at file offset {pos:#x}");
        }
        let entries: &[RelocEntry] =
            bytemuck::cast_slice(&reloc_data[pos + header_size..block_end]);
        pos = block_end;
        for RelocEntry { entry } in entries {
            if entry >> 12 != 3 {
                continue;
            }
            let site_rva = (page_rva + u32::from(entry & 0x0fff)).to_usize();
            let Some(raw_value) = u32_at(exe, env.image_base.to_usize(), site_rva) else {
                continue;
            };
            let target_rva = raw_value.wrapping_sub(env.image_base).to_usize();
            let Some(target_section) = target_section_at(env, target_rva) else {
                continue;
            };
            relevant += 1;
            if pdb_owns(symbols, target_section, target_rva) {
                continue;
            }
            let source_section =
                source_section_at(exe, env.image_base.to_usize(), site_rva)
                    .unwrap_or("outside");
            let (source_module, source_archive, source_start, source_size) =
                contribution_owner(
                env,
                symbols,
                &contributions,
                site_rva,
            );
            let (target_module, target_archive, target_start, target_size) =
                contribution_owner(
                env,
                symbols,
                &contributions,
                target_rva,
            );
            rows.push((
                site_rva,
                source_section.to_owned(),
                target_rva,
                target_section,
                source_module,
                source_archive,
                source_start,
                source_size,
                target_module,
                target_archive,
                target_start,
                target_size,
                "no exact or extent-backed PDB symbol",
            ));
        }
    }
    rows.sort_unstable_by_key(|row| (row.0, row.2));

    let mut output = String::with_capacity(rows.len() * 72);
    writeln!(output, "# relevant_xrefs={relevant}")?;
    writeln!(
        output,
        "# pdb_owned_xrefs={}", relevant - rows.len()
    )?;
    output.push_str(HEADER);
    for (site, source, target, section, source_module, source_archive,
         source_start, source_size, target_module, target_archive,
         target_start, target_size, reason) in &rows {
        writeln!(
            output,
            "{site:#x}\t{source}\t{target:#x}\t{section}\t{source_module}\t\
             {source_archive}\t{source_start:#x}\t{source_size:#x}\t\
             {target_module}\t{target_archive}\t{target_start:#x}\t\
             {target_size:#x}\t{reason}",
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
    symbols: &PdbSymbols,
    contributions: &[pdb2::DBISectionContribution],
    target_rva: usize,
) -> (String, String, usize, usize) {
    let section_offset = [env.text, env.rdata, env.data]
        .into_iter()
        .find_map(|section| {
            contains(section, target_rva, 1)
                .then_some((section.id, target_rva - section.rva, section.rva))
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
            let (module, archive) = symbols.modules
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

fn pdb_owns(symbols: &PdbSymbols, section: &str, target_rva: usize) -> bool {
    if symbols.symbol_starts.contains(&target_rva) {
        return true;
    }
    match section {
        ".text" => {
            let Some((rva, _)) = symbols.functions.range(..=target_rva).next_back() else {
                return false;
            };
            if *rva == target_rva {
                return true;
            }
            symbols
                .function_sizes
                .get(rva)
                .is_some_and(|size| target_rva - *rva < *size)
        }
        ".rdata" => {
            let in_string = symbols
                .strings
                .range(..=target_rva)
                .next_back()
                .is_some_and(|(rva, (_, data))| target_rva - *rva < data.len());
            in_string || symbols.constants.contains_key(&target_rva)
        }
        ".data" | ".bss" => symbols.statics.contains_key(&target_rva),
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

fn u32_at(
    exe: &object::read::pe::PeFile32<'_>,
    image_base: usize,
    rva: usize,
) -> Option<u32> {
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
