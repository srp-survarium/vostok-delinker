use crate::manifest_tsv::{self, column, field};

use nom::{IResult, Parser};

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Each row states the section-definition checksum to replay.
const CHECKSUM_HEADER: &[u8] = b"object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tchecksum\tcomdat_selection\tassociative_ordinal\tstorage";

/// Each row states its evidence instead of a checksum; every section-definition
/// checksum of an object is then written as zero.
const PROVENANCE_HEADER: &[u8] = b"object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage\tprovenance";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Schema {
    Checksum,
    Provenance,
}

const SCHEMAS: &[(&[u8], Schema)] = &[
    (CHECKSUM_HEADER, Schema::Checksum),
    (PROVENANCE_HEADER, Schema::Provenance),
];

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    object: &'a [u8],
    ordinal: &'a [u8],
    name: &'a [u8],
    rva: &'a [u8],
    size: &'a [u8],
    alignment: &'a [u8],
    characteristics: &'a [u8],
    checksum: Option<&'a [u8]>,
    comdat_selection: &'a [u8],
    associative_ordinal: &'a [u8],
    storage: &'a [u8],
    provenance: Option<&'a [u8]>,
}

fn checksum_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, (object, ordinal, name, rva, size, alignment, characteristics, checksum)) = (
        column, column, column, column, column, column, column, column,
    )
        .parse(input)?;
    let (input, (comdat_selection, associative_ordinal, storage)) =
        (column, column, field).parse(input)?;
    Ok((
        input,
        ManifestRow {
            object,
            ordinal,
            name,
            rva,
            size,
            alignment,
            characteristics,
            checksum: Some(checksum),
            comdat_selection,
            associative_ordinal,
            storage,
            provenance: None,
        },
    ))
}

fn provenance_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, (object, ordinal, name, rva, size, alignment, characteristics)) =
        (column, column, column, column, column, column, column).parse(input)?;
    let (input, (comdat_selection, associative_ordinal, storage, provenance)) =
        (column, column, column, field).parse(input)?;
    Ok((
        input,
        ManifestRow {
            object,
            ordinal,
            name,
            rva,
            size,
            alignment,
            characteristics,
            checksum: None,
            comdat_selection,
            associative_ordinal,
            storage,
            provenance: Some(provenance),
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
    pub checksum: u32,
    pub comdat_selection: ComdatSelection,
    pub associative_ordinal: Option<usize>,
    pub storage: Option<SectionStorage>,
}

/// How every emitted object lays out its sections. The choice is global: a
/// section manifest makes it `Exact` for objects it does not list too.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SectionTopology {
    /// Each object opens with `.data`, `.rdata` and `.text`, in that order,
    /// whether or not they receive contents.
    #[default]
    Synthesized,
    /// An object holds the manifest's sections in ordinal order, then only
    /// the default sections it needs, in the order it first needs them.
    Exact,
}

/// How the section-definition checksums of emitted objects are written.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SectionChecksums {
    /// The writer's own checksum, except where a manifest row states one.
    #[default]
    Reviewed,
    /// Zero in every section definition of every object.
    Zero,
}

#[derive(Default)]
pub struct DataSectionManifest {
    sections: Vec<DataSection>,
    topology: SectionTopology,
    checksums: SectionChecksums,
}

impl DataSectionManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let (schema, rows) = manifest_tsv::read(bytes, path, "data section manifest", SCHEMAS)?;
        let mut sections = Vec::new();
        let mut ordinals = HashSet::new();

        for line in rows {
            let row = match schema {
                Schema::Checksum => line.columns(checksum_row, "eleven")?,
                Schema::Provenance => line.columns(provenance_row, "eleven")?,
            };
            if let Some(provenance) = row.provenance {
                line.non_empty_text("provenance", provenance)?;
            }
            let object = line.object(row.object)?;
            let ordinal = line.number("ordinal", row.ordinal)?;
            if ordinal == 0 || !ordinals.insert((object, ordinal)) {
                anyhow::bail!("{line}: section ordinal must be unique and non-zero per object");
            }
            if row.name.is_empty()
                || row.name.len() > 8
                || row.name.iter().any(|byte| byte.is_ascii_control())
            {
                anyhow::bail!("{line}: section name must contain one to eight printable bytes");
            }
            let rva = line.optional_number("rva", row.rva)?;
            let size = line.number("size", row.size)?;
            let alignment = line.number("alignment", row.alignment)? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!("{line}: section alignment must be a non-zero power of two");
            }
            let characteristics = line.u32("characteristics", row.characteristics)?;
            let checksum = match row.checksum {
                Some(checksum) => line.u32("checksum", checksum)?,
                None => 0,
            };
            let comdat_selection = match line.number("comdat_selection", row.comdat_selection)? {
                0 => ComdatSelection::None,
                1 => ComdatSelection::NoDuplicates,
                2 => ComdatSelection::Any,
                3 => ComdatSelection::SameSize,
                4 => ComdatSelection::ExactMatch,
                5 => ComdatSelection::Associative,
                6 => ComdatSelection::Largest,
                7 => ComdatSelection::Newest,
                _ => anyhow::bail!("{line}: unsupported COMDAT selection"),
            };
            let associative_ordinal =
                line.optional_number("associative_ordinal", row.associative_ordinal)?;
            if (comdat_selection == ComdatSelection::Associative) != associative_ordinal.is_some() {
                anyhow::bail!("{line}: associative COMDAT selection/ordinal mismatch");
            }
            let storage = match row.storage {
                b"-" => None,
                b"data" => Some(SectionStorage::Data),
                b"rdata" => Some(SectionStorage::Rdata),
                b"bss" => Some(SectionStorage::Bss),
                value => anyhow::bail!(
                    "{line}: unsupported section storage {}",
                    String::from_utf8_lossy(value)
                ),
            };
            if rva.is_some() && storage.is_none() {
                anyhow::bail!("{line}: an assigned data section RVA requires a storage class");
            }
            if let Some(rva) = rva {
                if rva & (alignment as usize - 1) != 0 || rva.checked_add(size).is_none() {
                    anyhow::bail!(
                        "{line}: data section RVA/extent violates alignment or overflows"
                    );
                }
            }
            let expected_alignment_bits = (alignment.trailing_zeros() + 1) << 20;
            if alignment > 8192
                || characteristics & object::pe::IMAGE_SCN_ALIGN_MASK != expected_alignment_bits
            {
                anyhow::bail!("{line}: section alignment disagrees with its characteristics");
            }
            let comdat_flag = characteristics & object::pe::IMAGE_SCN_LNK_COMDAT != 0;
            if comdat_flag != (comdat_selection != ComdatSelection::None) {
                anyhow::bail!("{line}: COMDAT characteristic/selection mismatch");
            }
            if let Some(storage) = storage {
                // A `$` suffix is only the linker's ordering key within a group:
                // `.rdata$r` holds cl's RTTI records and `.xdata$x` its exception
                // tables, and both link into read-only data.
                let group = match row.name.iter().position(|byte| *byte == b'$') {
                    Some(index) => &row.name[..index],
                    None => row.name,
                };
                let (name_matches, required, forbidden) = match storage {
                    SectionStorage::Data => (
                        group == b".data" || group == b".CRT",
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                    ),
                    SectionStorage::Rdata => (
                        group == b".rdata" || group == b".xdata",
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA,
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                            | object::pe::IMAGE_SCN_CNT_CODE
                            | object::pe::IMAGE_SCN_MEM_EXECUTE
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                    ),
                    SectionStorage::Bss => (
                        group == b".bss",
                        object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                            | object::pe::IMAGE_SCN_MEM_WRITE,
                        object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA,
                    ),
                };
                if !name_matches
                    || characteristics & required != required
                    || characteristics & forbidden != 0
                {
                    anyhow::bail!(
                        "{line}: storage does not match candidate section name/characteristics"
                    );
                }
            }
            sections.push(DataSection {
                object,
                ordinal,
                name: row.name.to_vec().leak(),
                rva,
                size,
                alignment,
                characteristics,
                checksum,
                comdat_selection,
                associative_ordinal,
                storage,
            });
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
                    && (leader >= section.ordinal
                        || !rows.iter().any(|row| {
                            row.ordinal == leader
                                && !matches!(
                                    row.comdat_selection,
                                    ComdatSelection::None | ComdatSelection::Associative
                                )
                        }))
                {
                    anyhow::bail!(
                        "{}: object {} has invalid associative section ordinal",
                        path.display(),
                        String::from_utf8_lossy(object)
                    );
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
        Ok(Self {
            sections,
            topology: SectionTopology::Exact,
            checksums: match schema {
                Schema::Checksum => SectionChecksums::Reviewed,
                Schema::Provenance => SectionChecksums::Zero,
            },
        })
    }

    pub fn sections(&self) -> &[DataSection] {
        &self.sections
    }

    pub fn topology(&self) -> SectionTopology {
        self.topology
    }

    pub fn checksums(&self) -> SectionChecksums {
        self.checksums
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
        && matches!(
            first.comdat_selection,
            ComdatSelection::Any
                | ComdatSelection::SameSize
                | ComdatSelection::ExactMatch
                | ComdatSelection::Largest
                | ComdatSelection::Newest
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TEXT: &str = "object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tchecksum\tcomdat_selection\tassociative_ordinal\tstorage\n";

    fn parse(rows: &str) -> anyhow::Result<DataSectionManifest> {
        DataSectionManifest::parse(
            format!("{HEADER_TEXT}{rows}").as_bytes(),
            Path::new("test.tsv"),
        )
    }

    #[test]
    fn preserves_duplicate_data_sections_and_comdat_metadata() {
        let manifest = parse(
            "BASE/Midi.c\t1\t.data\t0x100\t0x48\t8\t0xc0400040\t0\t0\t-\tdata\n\
             BASE/Midi.c\t2\t.data\t0x148\t0x11\t4\t0xc0301040\t0\t2\t-\tdata\n",
        )
        .unwrap();
        assert_eq!(manifest.sections().len(), 2);
        assert_eq!(manifest.sections()[1].checksum, 0);
        assert_eq!(
            manifest.sections()[1].comdat_selection,
            ComdatSelection::Any
        );
        assert_eq!(manifest.sections()[1].storage, Some(SectionStorage::Data));
    }

    const PROVENANCE_HEADER_TEXT: &str = "object\tordinal\tname\trva\tsize\talignment\tcharacteristics\tcomdat_selection\tassociative_ordinal\tstorage\tprovenance\n";

    fn parse_provenance(rows: &str) -> anyhow::Result<DataSectionManifest> {
        DataSectionManifest::parse(
            format!("{PROVENANCE_HEADER_TEXT}{rows}").as_bytes(),
            Path::new("test.tsv"),
        )
    }

    #[test]
    fn header_selects_the_checksum_policy() {
        assert_eq!(
            DataSectionManifest::default().checksums(),
            SectionChecksums::Reviewed
        );
        assert_eq!(parse("").unwrap().checksums(), SectionChecksums::Reviewed);

        let manifest = parse_provenance(
            "u.c\t1\t.data\t0x100\t0x48\t8\t0xc0401040\t2\t-\tdata\tcandidate-COFF-section\n",
        )
        .unwrap();
        assert_eq!(manifest.checksums(), SectionChecksums::Zero);
        assert_eq!(manifest.sections()[0].checksum, 0);
        assert_eq!(
            manifest.sections()[0].comdat_selection,
            ComdatSelection::Any
        );
        assert_eq!(manifest.topology(), SectionTopology::Exact);
    }

    #[test]
    fn provenance_rows_require_printable_evidence() {
        for provenance in ["", "bad\x01"] {
            let error = parse_provenance(&format!(
                "u.c\t1\t.data\t0x100\t4\t4\t0xc0300040\t0\t-\tdata\t{provenance}\n"
            ))
            .err()
            .unwrap()
            .to_string();
            assert!(error.contains("provenance"), "{error}");
        }
        let error = parse_provenance("u.c\t1\t.data\t0x100\t4\t4\t0xc0300040\t0\t-\tdata\n")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("eleven"), "{error}");
    }

    #[test]
    fn supplied_manifest_selects_exact_topology_without_rows() {
        assert_eq!(
            DataSectionManifest::default().topology(),
            SectionTopology::Synthesized
        );
        assert_eq!(parse("").unwrap().topology(), SectionTopology::Exact);
    }

    #[test]
    fn validates_contiguous_and_associative_ordinals() {
        assert!(parse("a.c\t2\t.data\t0x100\t4\t4\t0\t0\t0\t-\tdata\n").is_err());
        assert!(parse("a.c\t1\t.debug$F\t-\t4\t1\t0\t0\t5\t2\t-\n").is_err());

        let leader = "a.c\t1\t.data\t0x100\t4\t4\t0xc0301040\t0\t2\t-\tdata\n";
        let associative = "a.c\t2\t.debug$F\t-\t4\t1\t0x42101040\t0\t5\t1\t-\n";
        assert!(parse(&format!("{leader}{associative}")).is_ok());
        let chained = "a.c\t3\t.debug$F\t-\t4\t1\t0x42101040\t0\t5\t2\t-\n";
        assert!(parse(&format!("{leader}{associative}{chained}")).is_err());
    }

    #[test]
    fn permits_storage_assigned_sections_without_an_affine_retail_rva() {
        let manifest = parse("a.c\t1\t.data\t-\t0x10\t8\t0xc0400040\t0\t0\t-\tdata\n").unwrap();
        assert_eq!(manifest.sections()[0].rva, None);
        assert_eq!(manifest.sections()[0].storage, Some(SectionStorage::Data));
    }

    #[test]
    fn accepts_linker_sorted_initialized_writable_sections() {
        let manifest = parse("a.c\t1\t.CRT$XCU\t0x100\t4\t4\t0xc0300040\t0\t0\t-\tdata\n").unwrap();
        assert_eq!(manifest.sections()[0].storage, Some(SectionStorage::Data));
    }

    #[test]
    fn grouped_section_names_select_storage_by_their_group() {
        for (name, alignment, characteristics, comdat, storage) in [
            (".rdata$r", 4, "0x40301040", 2, "rdata"),
            (".xdata$x", 8, "0x40401040", 2, "rdata"),
            (".data$1", 4, "0xc0300040", 0, "data"),
            (".bss$1", 4, "0xc0300080", 0, "bss"),
        ] {
            let row = format!(
                "a.c\t1\t{name}\t0x100\t8\t{alignment}\t{characteristics}\t0\t{comdat}\t-\t{storage}\n"
            );
            assert!(parse(&row).is_ok(), "rejected {name}");
        }
        for (name, characteristics, storage) in [
            (".rdatax", "0x40300040", "rdata"),
            (".text$x", "0x40300040", "rdata"),
            (".xdata$x", "0x60300020", "rdata"),
            (".xdata$x", "0xc0300040", "data"),
        ] {
            let row =
                format!("a.c\t1\t{name}\t0x100\t8\t4\t{characteristics}\t0\t0\t-\t{storage}\n");
            assert!(parse(&row).is_err(), "accepted {name} {characteristics}");
        }
    }

    #[test]
    fn rejects_misaligned_overlapping_and_storage_inconsistent_sections() {
        assert!(parse("a.c\t1\t.data\t0x102\t4\t4\t0xc0300040\t0\t0\t-\tdata\n").is_err());
        assert!(parse("a.c\t1\t.data\t0x100\t4\t8\t0xc0300040\t0\t0\t-\tdata\n").is_err());
        assert!(
            parse(
                "a.c\t1\t.data\t0x100\t8\t4\t0xc0300040\t0\t0\t-\tdata\n\
                 b.c\t1\t.data\t0x104\t4\t4\t0xc0300040\t0\t0\t-\tdata\n"
            )
            .is_err()
        );
        assert!(parse("a.c\t1\t.rdata\t0x100\t4\t4\t0xc0300040\t0\t0\t-\trdata\n").is_err());
        assert!(
            parse(
                "a.c\t1\t.text\t-\t4\t1\t0x00100020\t0\t0\t-\t-\n\
                 a.c\t2\t.debug$F\t-\t4\t1\t0x00101040\t0\t5\t1\t-\n"
            )
            .is_err()
        );
    }

    #[test]
    fn permits_only_exact_compatible_folded_comdat_aliases() {
        let alias = concat!(
            "a.c\t1\t.rdata\t0x100\t4\t4\t0x40301040\t0\t2\t-\trdata\n",
            "b.c\t1\t.rdata\t0x100\t4\t4\t0x40301040\t0\t2\t-\trdata\n",
        );
        assert!(parse(alias).is_ok());

        let partial = alias.replace("b.c\t1\t.rdata\t0x100\t4", "b.c\t1\t.rdata\t0x102\t2");
        assert!(parse(&partial).is_err());
        let ordinary = alias.replace("0x40301040\t0\t2", "0x40300040\t0\t0");
        assert!(parse(&ordinary).is_err());
        let selection_mismatch = alias.replacen("0x40301040\t0\t2", "0x40301040\t0\t3", 1);
        assert!(parse(&selection_mismatch).is_err());
    }

    #[test]
    fn accepts_crlf_and_missing_final_line_ending() {
        let text = format!(
            "{}a.c\t1\t.data\t0x100\t4\t4\t0xc0300040\t0\t0\t-\tdata",
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
