use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};

use std::collections::{HashMap, HashSet};
use std::path::Path;

const HEADER: &[u8] = b"object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage";

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    object: &'a [u8],
    ordinal: &'a [u8],
    name: &'a [u8],
    rva: &'a [u8],
    size: &'a [u8],
    alignment: &'a [u8],
    characteristics: &'a [u8],
    comdat_selection: &'a [u8],
    associative_ordinal: &'a [u8],
    storage: &'a [u8],
}

fn manifest_lines(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    terminated(
        separated_list0(line_ending, not_line_ending),
        opt(line_ending),
    )
    .parse(input)
}

fn field(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_till(|byte| byte == b'\t').parse(input)
}

fn manifest_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, fields) = (
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        field,
    )
        .parse(input)?;
    Ok((
        input,
        ManifestRow {
            object: fields.0,
            ordinal: fields.1,
            name: fields.2,
            rva: fields.3,
            size: fields.4,
            alignment: fields.5,
            characteristics: fields.6,
            comdat_selection: fields.7,
            associative_ordinal: fields.8,
            storage: fields.9,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionStorage {
    Data,
    Rdata,
    Bss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComdatSelection {
    None,
    NoDuplicates,
    Any,
    SameSize,
    ExactMatch,
    Associative,
    Largest,
    Newest,
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
    pub comdat_selection: ComdatSelection,
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
        let (_, lines) = all_consuming(manifest_lines)
            .parse(bytes)
            .map_err(|_| anyhow::anyhow!("{}: invalid line ending", path.display()))?;
        let mut sections = Vec::new();
        let mut ordinals = HashSet::new();
        let mut saw_header = false;

        for (line_index, line) in lines.into_iter().enumerate() {
            let line_number = line_index + 1;
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
            if line == HEADER {
                anyhow::bail!(
                    "{}:{}: duplicate data section manifest header",
                    path.display(),
                    line_number
                );
            }
            let (_, row) = all_consuming(manifest_row).parse(line).map_err(|_| {
                anyhow::anyhow!(
                    "{}:{}: expected exactly ten tab-separated columns",
                    path.display(),
                    line_number
                )
            })?;
            let object = normalize_object(row.object, path, line_number)?;
            let ordinal = parse_number(row.ordinal)?;
            if ordinal == 0 || !ordinals.insert((object, ordinal)) {
                anyhow::bail!(
                    "{}:{}: section ordinal must be unique and non-zero per object",
                    path.display(),
                    line_number
                );
            }
            if row.name.is_empty()
                || row.name.len() > 8
                || row.name.iter().any(|byte| byte.is_ascii_control())
            {
                anyhow::bail!(
                    "{}:{}: section name must contain one to eight printable bytes",
                    path.display(),
                    line_number
                );
            }
            let rva = parse_optional_number(row.rva)?;
            let size = parse_number(row.size)?;
            let alignment = parse_number(row.alignment)? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!(
                    "{}:{}: section alignment must be a non-zero power of two",
                    path.display(),
                    line_number
                );
            }
            let characteristics = u32::try_from(parse_number(row.characteristics)?)?;
            let comdat_selection = match parse_number(row.comdat_selection)? {
                0 => ComdatSelection::None,
                1 => ComdatSelection::NoDuplicates,
                2 => ComdatSelection::Any,
                3 => ComdatSelection::SameSize,
                4 => ComdatSelection::ExactMatch,
                5 => ComdatSelection::Associative,
                6 => ComdatSelection::Largest,
                7 => ComdatSelection::Newest,
                _ => anyhow::bail!(
                    "{}:{}: unsupported COMDAT selection",
                    path.display(),
                    line_number
                ),
            };
            let associative_ordinal = parse_optional_number(row.associative_ordinal)?;
            if (comdat_selection == ComdatSelection::Associative) != associative_ordinal.is_some() {
                anyhow::bail!(
                    "{}:{}: associative COMDAT selection/ordinal mismatch",
                    path.display(),
                    line_number
                );
            }
            let storage = match row.storage {
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
                    "{}:{}: data section storage and RVA must both be present or absent",
                    path.display(),
                    line_number
                );
            }
            sections.push(DataSection {
                object,
                ordinal,
                name: row.name.to_vec().leak(),
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

        sections.sort_unstable_by_key(|section| (section.object, section.ordinal));
        let mut by_object = HashMap::<&[u8], Vec<&DataSection>>::new();
        for section in &sections {
            by_object.entry(section.object).or_default().push(section);
        }
        for (object, rows) in by_object {
            for (index, section) in rows.iter().enumerate() {
                if section.ordinal != index + 1 {
                    anyhow::bail!(
                        "{}: object {} section ordinals must be contiguous from one",
                        path.display(),
                        String::from_utf8_lossy(object)
                    );
                }
                if let Some(leader) = section.associative_ordinal
                    && (leader >= section.ordinal || !rows.iter().any(|row| row.ordinal == leader))
                {
                    anyhow::bail!(
                        "{}: object {} has invalid associative section ordinal",
                        path.display(),
                        String::from_utf8_lossy(object)
                    );
                }
            }
        }
        Ok(Self { sections })
    }

    pub fn sections(&self) -> &[DataSection] {
        &self.sections
    }
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

fn parse_optional_number(value: &[u8]) -> anyhow::Result<Option<usize>> {
    if value == b"-" {
        Ok(None)
    } else {
        Ok(Some(parse_number(value)?))
    }
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

    const HEADER_TEXT: &str = "object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage\n";

    fn parse(rows: &str) -> anyhow::Result<DataSectionManifest> {
        DataSectionManifest::parse(
            format!("{HEADER_TEXT}{rows}").as_bytes(),
            Path::new("test.tsv"),
        )
    }

    #[test]
    fn preserves_duplicate_data_sections_and_comdat_metadata() {
        let manifest = parse(
            "BASE/Midi.c\t1\t.data\t0x100\t0x48\t8\t0xc0400040\t0\t-\tdata\n\
             BASE/Midi.c\t2\t.data\t0x148\t0x11\t4\t0xc0301040\t2\t-\tdata\n",
        )
        .unwrap();
        assert_eq!(manifest.sections().len(), 2);
        assert_eq!(
            manifest.sections()[1].comdat_selection,
            ComdatSelection::Any
        );
        assert_eq!(manifest.sections()[1].storage, Some(SectionStorage::Data));
    }

    #[test]
    fn validates_contiguous_and_associative_ordinals() {
        assert!(parse("a.c\t2\t.data\t0x100\t4\t4\t0\t0\t-\tdata\n").is_err());
        assert!(parse("a.c\t1\t.debug$F\t-\t4\t1\t0\t5\t2\t-\n").is_err());
    }

    #[test]
    fn accepts_crlf_and_missing_final_line_ending() {
        let text = format!(
            "{}a.c\t1\t.data\t0x100\t4\t4\t0\t0\t-\tdata",
            HEADER_TEXT.replace('\n', "\r\n")
        );
        assert_eq!(
            DataSectionManifest::parse(text.as_bytes(), Path::new("test.tsv"))
                .unwrap()
                .sections()
                .len(),
            1
        );
    }
}
