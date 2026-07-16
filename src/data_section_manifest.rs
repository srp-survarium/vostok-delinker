use std::collections::{HashMap, HashSet};
use std::path::Path;

const HEADER: &[u8] = b"object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage\tprovenance";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SectionStorage {
    Data,
    Rdata,
    Bss,
}

#[derive(Clone, Copy, Debug)]
pub struct DataSection {
    pub object: &'static [u8],
    pub ordinal: usize,
    pub name: &'static [u8],
    pub rva: Option<usize>,
    pub size: usize,
    pub alignment: u64,
    pub characteristics: u32,
    pub comdat_selection: u8,
    pub associative_ordinal: Option<usize>,
    pub storage: Option<SectionStorage>,
}

#[derive(Default)]
pub struct DataSectionManifest {
    sections: Vec<DataSection>,
}

impl DataSectionManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let mut sections = Vec::new();
        let mut ordinals = HashSet::new();
        let mut saw_header = false;
        for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            let line_number = line_index + 1;
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            if !saw_header {
                if line != HEADER {
                    anyhow::bail!(
                        "{}:{}: invalid data section manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            let columns = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            if columns.len() != 11 {
                anyhow::bail!(
                    "{}:{}: expected exactly eleven tab-separated columns",
                    path.display(),
                    line_number
                );
            }
            let object = normalize_object(columns[0], path, line_number)?;
            let ordinal = parse_number(columns[1])?;
            if ordinal == 0 || !ordinals.insert((object, ordinal)) {
                anyhow::bail!(
                    "{}:{}: section ordinal must be unique and non-zero per object",
                    path.display(),
                    line_number
                );
            }
            let name: &'static [u8] = columns[2].to_vec().leak();
            if name.is_empty() || name.len() > 8 || name.iter().any(|byte| byte.is_ascii_control())
            {
                anyhow::bail!(
                    "{}:{}: section name must contain one to eight printable bytes",
                    path.display(),
                    line_number
                );
            }
            let rva = if columns[3] == b"-" {
                None
            } else {
                Some(parse_number(columns[3])?)
            };
            let size = parse_number(columns[4])?;
            let alignment = parse_number(columns[5])? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!(
                    "{}:{}: section alignment must be a non-zero power of two",
                    path.display(),
                    line_number
                );
            }
            let characteristics = u32::try_from(parse_number(columns[6])?)?;
            let comdat_selection = u8::try_from(parse_number(columns[7])?)?;
            if comdat_selection > 7 {
                anyhow::bail!(
                    "{}:{}: unsupported COMDAT selection",
                    path.display(),
                    line_number
                );
            }
            let associative_ordinal = if columns[8] == b"-" {
                None
            } else {
                Some(parse_number(columns[8])?)
            };
            if (comdat_selection == 5) != associative_ordinal.is_some() {
                anyhow::bail!(
                    "{}:{}: associative COMDAT selection/ordinal mismatch",
                    path.display(),
                    line_number
                );
            }
            let storage = match columns[9] {
                b"-" => None,
                b"data" => Some(SectionStorage::Data),
                b"rdata" => Some(SectionStorage::Rdata),
                b"bss" => Some(SectionStorage::Bss),
                value => anyhow::bail!(
                    "{}:{}: unsupported section storage {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(value)
                ),
            };
            if storage.is_some() != rva.is_some() {
                anyhow::bail!(
                    "{}:{}: data section storage/RVA must both be present or absent",
                    path.display(),
                    line_number
                );
            }
            if let Some(rva) = rva {
                if rva & (alignment as usize - 1) != 0 || rva.checked_add(size).is_none() {
                    anyhow::bail!(
                        "{}:{}: data section RVA/extent violates alignment or overflows",
                        path.display(),
                        line_number
                    );
                }
            }
            let comdat_flag = characteristics & object::pe::IMAGE_SCN_LNK_COMDAT != 0;
            if comdat_flag != (comdat_selection != 0) {
                anyhow::bail!(
                    "{}:{}: COMDAT characteristic/selection mismatch",
                    path.display(),
                    line_number
                );
            }
            if let Some(storage) = storage {
                let (expected_name, required, forbidden) = match storage {
                    SectionStorage::Data => (
                        b".data".as_slice(),
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                    ),
                    SectionStorage::Rdata => (
                        b".rdata".as_slice(),
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA,
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                    ),
                    SectionStorage::Bss => (
                        b".bss".as_slice(),
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA,
                    ),
                };
                if name != expected_name
                    || characteristics & required != required
                    || characteristics & forbidden != 0
                {
                    anyhow::bail!(
                        "{}:{}: storage does not match candidate section name/characteristics",
                        path.display(),
                        line_number
                    );
                }
            }
            if columns[10].is_empty() || columns[10].iter().any(|byte| byte.is_ascii_control()) {
                anyhow::bail!(
                    "{}:{}: provenance must be non-empty printable text",
                    path.display(),
                    line_number
                );
            }
            sections.push(DataSection {
                object,
                ordinal,
                name,
                rva,
                size,
                alignment,
                characteristics,
                comdat_selection,
                associative_ordinal,
                storage,
            });
        }
        if !saw_header {
            anyhow::bail!("{}: missing data section manifest header", path.display());
        }
        sections.sort_by_key(|section| (section.object, section.ordinal));
        let by_object = sections.iter().fold(
            HashMap::<&[u8], Vec<&DataSection>>::new(),
            |mut result, section| {
                result.entry(section.object).or_default().push(section);
                result
            },
        );
        for (object, rows) in by_object {
            for (index, section) in rows.iter().enumerate() {
                if section.ordinal != index + 1 {
                    anyhow::bail!(
                        "{}: object {} section ordinals must be contiguous from one",
                        path.display(),
                        String::from_utf8_lossy(object)
                    );
                }
                if let Some(leader) = section.associative_ordinal {
                    if leader >= section.ordinal || !rows.iter().any(|row| row.ordinal == leader) {
                        anyhow::bail!(
                            "{}: object {} has invalid associative section ordinal",
                            path.display(),
                            String::from_utf8_lossy(object)
                        );
                    }
                }
            }
        }
        let mut placed = sections
            .iter()
            .filter(|section| section.rva.is_some())
            .collect::<Vec<_>>();
        placed.sort_by_key(|section| {
            (
                section.rva.unwrap(),
                section.size,
                section.object,
                section.ordinal,
            )
        });
        for pair in placed.windows(2) {
            let first = pair[0];
            let second = pair[1];
            if first.rva.unwrap() + first.size > second.rva.unwrap()
                && !compatible_folded_comdat_alias(first, second)
            {
                anyhow::bail!(
                    "{}: overlapping assigned data sections {}:{} and {}:{}",
                    path.display(),
                    String::from_utf8_lossy(first.object),
                    first.ordinal,
                    String::from_utf8_lossy(second.object),
                    second.ordinal,
                );
            }
        }
        Ok(Self { sections })
    }

    pub fn sections(&self) -> &[DataSection] {
        &self.sections
    }
}

fn compatible_folded_comdat_alias(first: &DataSection, second: &DataSection) -> bool {
    first.object != second.object
        && first.rva == second.rva
        && first.size == second.size
        && first.name == second.name
        && first.alignment == second.alignment
        && first.characteristics == second.characteristics
        && first.storage == second.storage
        && first.comdat_selection == second.comdat_selection
        && matches!(first.comdat_selection, 2 | 3 | 4 | 6 | 7)
}

fn normalize_object(value: &[u8], path: &Path, line: usize) -> anyhow::Result<&'static [u8]> {
    let object = std::str::from_utf8(value)?.replace('/', "\\");
    if object.contains(':')
        || object
            .split('\\')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        anyhow::bail!(
            "{}:{}: object path must be relative and normalized",
            path.display(),
            line
        );
    }
    Ok(object.into_bytes().leak())
}

fn parse_number(value: &[u8]) -> anyhow::Result<usize> {
    let value = std::str::from_utf8(value)?;
    Ok(match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => usize::from_str_radix(hex, 16),
        None => value.parse(),
    }?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TEXT: &str = "object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage\tprovenance\n";

    fn parse(rows: &str) -> anyhow::Result<DataSectionManifest> {
        DataSectionManifest::parse(
            format!("{HEADER_TEXT}{rows}").as_bytes(),
            Path::new("test.tsv"),
        )
    }

    #[test]
    fn preserves_duplicate_data_sections_and_comdat_metadata() {
        let manifest = parse(
            "BASE/Midi.c\t1\t.data\t0x100\t0x48\t8\t0xc0400040\t0\t-\tdata\tcandidate\n\
             BASE/Midi.c\t2\t.data\t0x148\t0x11\t4\t0xc0301040\t2\t-\tdata\tcandidate\n",
        )
        .unwrap();
        assert_eq!(manifest.sections().len(), 2);
        assert_eq!(manifest.sections()[1].comdat_selection, 2);
        assert_eq!(manifest.sections()[1].storage, Some(SectionStorage::Data));
    }

    #[test]
    fn validates_contiguous_and_associative_ordinals() {
        assert!(parse("a.c\t2\t.data\t0x100\t4\t4\t0\t0\t-\tdata\ttest\n").is_err());
        assert!(parse("a.c\t1\t.debug$F\t-\t4\t1\t0\t5\t2\t-\ttest\n").is_err());
    }

    #[test]
    fn rejects_misaligned_overlapping_and_storage_inconsistent_sections() {
        assert!(parse("a.c\t1\t.data\t0x102\t4\t4\t0xc0300040\t0\t-\tdata\ttest\n").is_err());
        assert!(
            parse(
                "a.c\t1\t.data\t0x100\t8\t4\t0xc0300040\t0\t-\tdata\ttest\n\
             b.c\t1\t.data\t0x104\t4\t4\t0xc0300040\t0\t-\tdata\ttest\n"
            )
            .is_err()
        );
        assert!(parse("a.c\t1\t.rdata\t0x100\t4\t4\t0xc0300040\t0\t-\trdata\ttest\n").is_err());
    }

    #[test]
    fn permits_only_exact_compatible_folded_comdat_aliases() {
        let alias = concat!(
            "a.c\t1\t.rdata\t0x100\t4\t4\t0x40301040\t2\t-\trdata\ttest\n",
            "b.c\t1\t.rdata\t0x100\t4\t4\t0x40301040\t2\t-\trdata\ttest\n",
        );
        assert!(parse(alias).is_ok());

        let partial = alias.replace("b.c\t1\t.rdata\t0x100\t4", "b.c\t1\t.rdata\t0x102\t2");
        assert!(parse(&partial).is_err());
        let ordinary = alias.replace("0x40301040\t2", "0x40300040\t0");
        assert!(parse(&ordinary).is_err());
        let selection_mismatch = alias.replacen("0x40301040\t2", "0x40301040\t3", 1);
        assert!(parse(&selection_mismatch).is_err());
    }
}
