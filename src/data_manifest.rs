use pdb2::RawString;

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] =
    b"name\tobject\trva\tsize\tstorage\talignment\tsection_offset\tscope\tprovenance";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DataStorage {
    Data,
    Rdata,
    Bss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataScope {
    External,
    Local,
}

#[derive(Clone, Copy, Debug)]
pub struct DataDefinition {
    pub name: RawString<'static>,
    pub object: &'static [u8],
    pub rva: usize,
    pub size: usize,
    pub storage: DataStorage,
    pub alignment: u64,
    pub section_offset: Option<usize>,
    pub scope: DataScope,
    pub provisional: bool,
    pub address_authoritative: bool,
}

#[derive(Default)]
pub struct DataManifest {
    definitions: Vec<DataDefinition>,
    names: HashSet<&'static [u8]>,
    closed_groups: HashSet<(&'static [u8], DataStorage)>,
}

impl DataManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let mut definitions = Vec::new();
        let mut names = HashSet::new();
        let mut external_names = HashSet::new();
        let mut local_names = HashSet::new();
        let mut proved_rvas = HashSet::new();
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
                        "{}:{}: invalid data manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            if line == HEADER {
                anyhow::bail!(
                    "{}:{}: duplicate data manifest header",
                    path.display(),
                    line_number
                );
            }

            let columns = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            if columns.len() != 9 {
                anyhow::bail!(
                    "{}:{}: expected exactly nine tab-separated columns",
                    path.display(),
                    line_number
                );
            }
            validate_text(path, line_number, "name", columns[0])?;
            validate_text(path, line_number, "object", columns[1])?;
            validate_text(path, line_number, "scope", columns[7])?;
            validate_text(path, line_number, "provenance", columns[8])?;
            if columns[0].is_empty() || columns[1].is_empty() || columns[8].is_empty() {
                anyhow::bail!(
                    "{}:{}: name, object, and provenance must be non-empty",
                    path.display(),
                    line_number
                );
            }

            let name: &'static [u8] = columns[0].to_vec().leak();
            let object = std::str::from_utf8(columns[1])?.replace('/', "\\");
            if object.contains(':')
                || object
                    .split('\\')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                anyhow::bail!(
                    "{}:{}: object path must be relative and normalized",
                    path.display(),
                    line_number
                );
            }

            let rva = parse_number(columns[2])?;
            let size = parse_number(columns[3])?;
            if size == 0 {
                anyhow::bail!(
                    "{}:{}: data size must be non-zero",
                    path.display(),
                    line_number
                );
            }
            if rva.checked_add(size).is_none() {
                anyhow::bail!(
                    "{}:{}: data extent overflows the address space",
                    path.display(),
                    line_number
                );
            }
            let storage = match columns[4] {
                b"data" => DataStorage::Data,
                b"rdata" => DataStorage::Rdata,
                b"bss" => DataStorage::Bss,
                value => anyhow::bail!(
                    "{}:{}: unsupported storage {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(value)
                ),
            };
            let alignment = parse_number(columns[5])? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!(
                    "{}:{}: alignment must be a non-zero power of two",
                    path.display(),
                    line_number
                );
            }
            let section_offset = if columns[6] == b"-" {
                None
            } else {
                Some(parse_number(columns[6])?)
            };
            let scope = match columns[7] {
                b"external" => DataScope::External,
                b"local" => DataScope::Local,
                value => anyhow::bail!(
                    "{}:{}: unsupported scope {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(value)
                ),
            };
            let provisional = columns[8].starts_with(b"provisional-");
            let address_authoritative = !provisional
                || columns[8] == b"provisional-candidate-coff-public-anchor"
                || columns[8]
                    .windows(b"source-reviewed-DATA".len())
                    .any(|window| window == b"source-reviewed-DATA");
            if address_authoritative && !proved_rvas.insert(rva) {
                anyhow::bail!("{}:{}: duplicate data RVA", path.display(), line_number);
            }
            let object: &'static [u8] = object.into_bytes().leak();
            match scope {
                DataScope::External if !external_names.insert(name) => {
                    anyhow::bail!(
                        "{}:{}: duplicate external data name",
                        path.display(),
                        line_number
                    );
                }
                DataScope::Local if !local_names.insert((object, name)) => {
                    anyhow::bail!(
                        "{}:{}: duplicate local data name in owner",
                        path.display(),
                        line_number
                    );
                }
                _ => {}
            }
            names.insert(name);
            definitions.push(DataDefinition {
                name: RawString::from(name),
                object,
                rva,
                size,
                storage,
                alignment,
                section_offset,
                scope,
                provisional,
                address_authoritative,
            });
        }
        if !saw_header {
            anyhow::bail!("{}: missing data manifest header", path.display());
        }

        definitions.sort_by_key(|definition| {
            (
                definition.object,
                definition.storage,
                definition.section_offset.unwrap_or(definition.rva),
                definition.rva,
            )
        });
        let mut by_rva = definitions.clone();
        by_rva.sort_by_key(|definition| definition.rva);
        for pair in by_rva.windows(2) {
            if !pair[0].provisional
                && !pair[1].provisional
                && pair[0].rva.checked_add(pair[0].size).unwrap() > pair[1].rva
            {
                anyhow::bail!("overlapping data manifest definitions");
            }
        }
        let closed_groups = definitions
            .iter()
            .filter_map(|definition| {
                definition
                    .section_offset
                    .filter(|_| !definition.provisional)
                    .map(|_| (definition.object, definition.storage))
            })
            .collect();
        Ok(Self {
            definitions,
            names,
            closed_groups,
        })
    }

    pub fn definitions(&self) -> &[DataDefinition] {
        &self.definitions
    }

    pub fn contains_name(&self, name: &[u8]) -> bool {
        self.names.contains(name)
    }

    pub fn owner_and_addend_for_rva(&self, rva: usize) -> Option<(DataDefinition, usize)> {
        self.definitions
            .iter()
            .copied()
            .filter(|definition| definition.address_authoritative)
            .find_map(|definition| {
                if definition.rva <= rva && rva - definition.rva < definition.size {
                    Some((definition, rva - definition.rva))
                } else {
                    None
                }
            })
    }

    pub fn hypothesis_owner_and_addend_for_rva(
        &self,
        rva: usize,
        storage: Option<DataStorage>,
        object: Option<&[u8]>,
    ) -> Option<(DataDefinition, u32)> {
        let candidates = self.definitions.iter().copied().filter(|definition| {
            storage.map_or(true, |expected| definition.storage == expected)
                && object.map_or(true, |owner| definition.object == owner)
        });
        let definition = candidates.min_by_key(|definition| {
            let contains = definition.rva <= rva && rva - definition.rva < definition.size;
            (
                !contains,
                definition.rva.abs_diff(rva),
                definition.section_offset.unwrap_or(definition.rva),
                definition.name.as_bytes(),
            )
        })?;
        Some((definition, (rva as u32).wrapping_sub(definition.rva as u32)))
    }

    pub fn is_closed(&self, object: &[u8], storage: DataStorage) -> bool {
        self.closed_groups.contains(&(object, storage))
    }
}

fn validate_text(path: &Path, line: usize, field: &str, value: &[u8]) -> anyhow::Result<()> {
    if value.iter().any(|byte| byte.is_ascii_control()) {
        anyhow::bail!(
            "{}:{}: {} contains a control byte",
            path.display(),
            line,
            field
        );
    }
    Ok(())
}

fn parse_number(value: &[u8]) -> anyhow::Result<usize> {
    let value = std::str::from_utf8(value)?;
    let result = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => usize::from_str_radix(hex, 16),
        None => value.parse(),
    }?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TEXT: &str =
        "name\tobject\trva\tsize\tstorage\talignment\tsection_offset\tscope\tprovenance\n";

    fn parse(body: &str) -> anyhow::Result<DataManifest> {
        DataManifest::parse(body.as_bytes(), Path::new("test.tsv"))
    }

    fn manifest(row: &str) -> String {
        format!("{HEADER_TEXT}{row}\n")
    }

    fn error(row: &str) -> String {
        parse(&manifest(row)).err().unwrap().to_string()
    }

    #[test]
    fn absent_manifest_preserves_empty_legacy_behavior() {
        let parsed = DataManifest::load(None).unwrap();
        assert!(parsed.definitions().is_empty());
    }

    #[test]
    fn accepts_comments_crlf_paths_and_all_storage_classes() {
        let text = concat!(
            "# generated evidence\r\n",
            "name\tobject\trva\tsize\tstorage\talignment\tsection_offset\tscope\tprovenance\r\n",
            "table\tengine/world.c\t0x100\t0x20\tdata\t0x4\t-\texternal\treviewed\r\n",
            "constant\tengine/constants.c\t0X200\t16\trdata\t8\t0\tlocal\treviewed\r\n",
            "scratch\tengine/state.c\t0x300\t4\tbss\t1\t0\tlocal\treviewed\r\n",
        );
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.definitions().len(), 3);
        let table = parsed
            .definitions()
            .iter()
            .find(|row| row.name.as_bytes() == b"table")
            .unwrap();
        assert_eq!(table.object, b"engine\\world.c");
        assert_eq!(table.storage, DataStorage::Data);
        assert_eq!(table.alignment, 4);
        assert!(parsed.contains_name(b"constant"));
        assert!(parsed.is_closed(b"engine\\constants.c", DataStorage::Rdata));
        assert!(!parsed.is_closed(b"engine\\world.c", DataStorage::Data));
    }

    #[test]
    fn rejects_missing_header() {
        assert!(
            parse("# only a comment\n")
                .err()
                .unwrap()
                .to_string()
                .contains("missing")
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_headers() {
        assert!(
            parse("name\tobject\trva\n")
                .err()
                .unwrap()
                .to_string()
                .contains("invalid")
        );
        let duplicate = format!("{HEADER_TEXT}{HEADER_TEXT}");
        assert!(
            parse(&duplicate)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn rejects_wrong_column_counts() {
        assert!(error("a\tu.c\t0x100\t4\tdata\t4").contains("exactly nine"));
        assert!(
            error("a\tu.c\t0x100\t4\tdata\t4\t-\texternal\ttest\textra").contains("exactly nine")
        );
    }

    #[test]
    fn rejects_absolute_drive_and_non_normalized_object_paths() {
        for object in [
            "/tmp/u.c",
            "\\tmp\\u.c",
            "C:\\src\\u.c",
            "C:u.c",
            "\\\\server\\share\\u.c",
            "a/../u.c",
            "a/./u.c",
            "a//u.c",
        ] {
            let row = format!("a\t{object}\t0x100\t4\tdata\t4\t-\texternal\ttest");
            assert!(
                error(&row).contains("relative and normalized"),
                "accepted {object}"
            );
        }
    }

    #[test]
    fn rejects_nul_and_control_bytes_in_text_fields() {
        for row in [
            "a\0b\tu.c\t0x100\t4\tdata\t4\t-\texternal\ttest",
            "a\tu\x7f.c\t0x100\t4\tdata\t4\t-\texternal\ttest",
            "a\tu.c\t0x100\t4\tdata\t4\t-\texternal\ttest\x01",
        ] {
            assert!(error(row).contains("control byte"));
        }
    }

    #[test]
    fn rejects_duplicate_names() {
        let text = format!(
            "{HEADER_TEXT}a\tone.c\t0x100\t4\tdata\t4\t-\texternal\ttest\na\ttwo.c\t0x200\t4\tdata\t4\t-\texternal\ttest\n"
        );
        assert!(
            parse(&text)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate external data name")
        );
    }

    #[test]
    fn local_names_are_unique_only_within_their_owner_object() {
        let parsed = parse(&format!(
            "{HEADER_TEXT}local\ta.c\t0x100\t4\tdata\t4\t0\tlocal\tone\n\
             local\tb.c\t0x104\t4\tdata\t4\t0\tlocal\ttwo\n"
        ))
        .unwrap();
        assert_eq!(parsed.definitions().len(), 2);

        let duplicate = format!(
            "{HEADER_TEXT}local\ta.c\t0x100\t4\tdata\t4\t0\tlocal\tone\n\
             local\ta.c\t0x104\t4\tdata\t4\t4\tlocal\ttwo\n"
        );
        assert!(
            parse(&duplicate)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate local data name in owner")
        );
    }

    #[test]
    fn rejects_duplicate_rvas() {
        let text = format!(
            "{HEADER_TEXT}a\tone.c\t0x100\t4\tdata\t4\t-\texternal\ttest\nb\ttwo.c\t0x100\t4\tdata\t4\t-\texternal\ttest\n"
        );
        assert!(
            parse(&text)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate data RVA")
        );
    }

    #[test]
    fn rejects_overlaps_across_owner_objects() {
        let text = format!(
            "{HEADER_TEXT}a\tone.c\t0x100\t0x20\tdata\t4\t-\texternal\ttest\nb\ttwo.c\t0x110\t4\tdata\t4\t-\texternal\ttest\n"
        );
        assert!(
            parse(&text)
                .err()
                .unwrap()
                .to_string()
                .contains("overlapping")
        );
    }

    #[test]
    fn accepts_adjacent_extents_across_owner_objects() {
        let text = format!(
            "{HEADER_TEXT}a\tone.c\t0x100\t0x20\tdata\t4\t-\texternal\ttest\nb\ttwo.c\t0x120\t4\tdata\t4\t-\texternal\ttest\n"
        );
        assert_eq!(parse(&text).unwrap().definitions().len(), 2);
    }

    #[test]
    fn provisional_extents_may_overlap_without_claiming_closed_ownership() {
        let parsed = parse(&format!(
            "{HEADER_TEXT}a\tone.c\t0x100\t0x20\tdata\t4\t0\texternal\tprovisional-replay\n\
             b\ttwo.c\t0x110\t4\tdata\t4\t0\texternal\tproved\n"
        ))
        .unwrap();
        assert_eq!(parsed.definitions().len(), 2);
        assert!(!parsed.is_closed(b"one.c", DataStorage::Data));
        assert!(parsed.is_closed(b"two.c", DataStorage::Data));
        assert_eq!(
            parsed.owner_and_addend_for_rva(0x110).unwrap().0.object,
            b"two.c"
        );
    }

    #[test]
    fn source_reviewed_provisional_address_is_authoritative() {
        let parsed = parse(&manifest(
            "source\tu.c\t0x100\t4\tdata\t4\t0\texternal\tprovisional-source-reviewed-DATA",
        ))
        .unwrap();
        assert_eq!(
            parsed.owner_and_addend_for_rva(0x100).unwrap().0.object,
            b"u.c"
        );
        assert!(!parsed.is_closed(b"u.c", DataStorage::Data));
    }

    #[test]
    fn rejects_extent_overflow_and_zero_size() {
        let overflow = format!("a\tu.c\t{}\t2\tdata\t4\t-\texternal\ttest", usize::MAX);
        assert!(error(&overflow).contains("overflows"));
        assert!(error("a\tu.c\t0x100\t0\tdata\t4\t-\texternal\ttest").contains("non-zero"));
    }

    #[test]
    fn rejects_zero_and_non_power_of_two_alignment() {
        assert!(error("a\tu.c\t0x100\t4\tdata\t0\t-\texternal\ttest").contains("power of two"));
        assert!(error("a\tu.c\t0x100\t4\tdata\t3\t-\texternal\ttest").contains("power of two"));
    }

    #[test]
    fn resolves_interior_owner_and_addend_at_exact_boundaries() {
        let parsed = parse(&manifest(
            "table\tu.c\t0x100\t0x20\tdata\t4\t-\texternal\ttest",
        ))
        .unwrap();
        assert!(parsed.owner_and_addend_for_rva(0xff).is_none());
        let (owner, addend) = parsed.owner_and_addend_for_rva(0x100).unwrap();
        assert_eq!(owner.name.as_bytes(), b"table");
        assert_eq!(addend, 0);
        assert_eq!(parsed.owner_and_addend_for_rva(0x10f).unwrap().1, 0xf);
        assert_eq!(parsed.owner_and_addend_for_rva(0x11f).unwrap().1, 0x1f);
        assert!(parsed.owner_and_addend_for_rva(0x120).is_none());
    }
}
