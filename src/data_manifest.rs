use crate::pdb_symbols::PdbSymbols;

use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};
use pdb2::RawString;

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] = b"object\trva\tsize\tstorage\talignment";

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    object: &'a [u8],
    rva: &'a [u8],
    size: &'a [u8],
    storage: &'a [u8],
    alignment: &'a [u8],
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
    let (input, (object, rva, size, storage, alignment)) = (
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
            object,
            rva,
            size,
            storage,
            alignment,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataStorage {
    Data,
    Rdata,
    Bss,
}

#[derive(Clone, Copy, Debug)]
pub struct DataDefinition {
    pub symbol_name: RawString<'static>,
    pub object: &'static [u8],
    pub rva: usize,
    pub size: usize,
    pub storage: DataStorage,
    pub alignment: u64,
}

#[derive(Default)]
pub struct DataManifest {
    definitions: Vec<DataDefinition>,
}

impl DataManifest {
    pub fn load(path: Option<&Path>, symbols: &PdbSymbols) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path, symbols)
    }

    fn parse(bytes: &[u8], path: &Path, symbols: &PdbSymbols) -> anyhow::Result<Self> {
        let mut definitions = Vec::new();
        let mut rvas = HashSet::new();
        let mut saw_header = false;

        let (_, lines) = all_consuming(manifest_lines)
            .parse(bytes)
            .map_err(|_| anyhow::anyhow!("{}: invalid line ending", path.display()))?;

        for (line_index, line) in lines.into_iter().enumerate() {
            let line_number = line_index + 1;
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

            let (_, row) = all_consuming(manifest_row).parse(line).map_err(|_| {
                anyhow::anyhow!(
                    "{}:{}: expected exactly five tab-separated columns",
                    path.display(),
                    line_number
                )
            })?;
            validate_text(path, line_number, "object", row.object)?;
            if row.object.is_empty() {
                anyhow::bail!(
                    "{}:{}: object must be non-empty",
                    path.display(),
                    line_number
                );
            }
            let object = std::str::from_utf8(row.object)?.replace('/', "\\");
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

            let rva = parse_number(row.rva)?;
            let size = parse_number(row.size)?;
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
            let storage = match row.storage {
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
            let alignment = parse_number(row.alignment)? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!(
                    "{}:{}: alignment must be a non-zero power of two",
                    path.display(),
                    line_number
                );
            }
            if !rvas.insert(rva) {
                anyhow::bail!("{}:{}: duplicate data RVA", path.display(), line_number);
            }

            let name = match storage {
                DataStorage::Data | DataStorage::Bss => symbols.statics.get(&rva).copied(),
                DataStorage::Rdata => symbols
                    .constants
                    .get(&rva)
                    .copied()
                    .or_else(|| symbols.strings.get(&rva).map(|(name, _)| *name)),
            }
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{}:{}: no compatible PDB data symbol starts at RVA {rva:#x}",
                    path.display(),
                    line_number
                )
            })?;

            let object: &'static [u8] = object.into_bytes().leak();
            definitions.push(DataDefinition {
                symbol_name: name,
                object,
                rva,
                size,
                storage,
                alignment,
            });
        }
        if !saw_header {
            anyhow::bail!("{}: missing data manifest header", path.display());
        }

        definitions.sort_unstable_by_key(|definition| definition.rva);
        for pair in definitions.windows(2) {
            if pair[0].rva.checked_add(pair[0].size).unwrap() > pair[1].rva {
                anyhow::bail!("overlapping data manifest definitions");
            }
        }
        Ok(Self { definitions })
    }

    pub fn definitions(&self) -> &[DataDefinition] {
        &self.definitions
    }

    pub fn owner_and_addend_for_rva(&self, rva: usize) -> Option<(DataDefinition, usize)> {
        let index = self
            .definitions
            .partition_point(|definition| definition.rva <= rva);
        let definition = *self.definitions.get(index.checked_sub(1)?)?;
        let addend = rva - definition.rva;
        (addend < definition.size).then_some((definition, addend))
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

    const HEADER_TEXT: &str = "object\trva\tsize\tstorage\talignment\n";

    fn symbols() -> PdbSymbols {
        let mut symbols = PdbSymbols::default();
        for (rva, name) in [
            (0x100, &b"table"[..]),
            (0x110, &b"overlap"[..]),
            (0x120, &b"adjacent"[..]),
            (0x140, &b"later"[..]),
            (0x180, &b"\x80raw"[..]),
            (0x300, &b"scratch"[..]),
        ] {
            symbols.statics.insert(rva, RawString::from(name));
        }
        symbols
            .constants
            .insert(0x200, RawString::from(&b"constant"[..]));
        symbols
    }

    fn parse(body: &str) -> anyhow::Result<DataManifest> {
        DataManifest::parse(body.as_bytes(), Path::new("test.tsv"), &symbols())
    }

    fn manifest(row: &str) -> String {
        format!("{HEADER_TEXT}{row}\n")
    }

    fn error(row: &str) -> String {
        parse(&manifest(row)).err().unwrap().to_string()
    }

    #[test]
    fn absent_manifest_supplies_no_reviewed_definitions() {
        let parsed = DataManifest::load(None, &symbols()).unwrap();
        assert!(parsed.definitions().is_empty());
    }

    #[test]
    fn accepts_comments_crlf_paths_and_all_storage_classes() {
        let text = concat!(
            "# generated evidence\r\n",
            "object\trva\tsize\tstorage\talignment\r\n",
            "engine/world.c\t0x100\t0x20\tdata\t0x4\r\n",
            "engine/constants.c\t0X200\t16\trdata\t8\r\n",
            "engine/state.c\t0x300\t4\tbss\t1\r\n",
        );
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.definitions().len(), 3);
        let table = parsed
            .definitions()
            .iter()
            .find(|row| row.symbol_name.as_bytes() == b"table")
            .unwrap();
        assert_eq!(table.object, b"engine\\world.c");
        assert_eq!(table.storage, DataStorage::Data);
        assert_eq!(table.alignment, 4);
        assert!(
            parsed
                .definitions()
                .iter()
                .any(|row| row.symbol_name.as_bytes() == b"constant")
        );
    }

    #[test]
    fn accepts_missing_final_line_ending_and_uses_raw_pdb_symbol_bytes() {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(b"\nu.c\t0x180\t4\tdata\t4");
        let parsed = DataManifest::parse(&bytes, Path::new("test.tsv"), &symbols()).unwrap();
        assert_eq!(parsed.definitions()[0].symbol_name.as_bytes(), b"\x80raw");
    }

    #[test]
    fn rejects_bare_carriage_return_line_endings() {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(b"\ru.c\t0x100\t4\tdata\t4");
        let error = DataManifest::parse(&bytes, Path::new("test.tsv"), &symbols())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("invalid line ending"));
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
            parse("object\trva\n")
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
        assert!(error("u.c\t0x100\t4\tdata").contains("exactly five"));
        assert!(error("u.c\t0x100\t4\tdata\t4\textra").contains("exactly five"));
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
            let row = format!("{object}\t0x100\t4\tdata\t4");
            assert!(
                error(&row).contains("relative and normalized"),
                "accepted {object}"
            );
        }
    }

    #[test]
    fn rejects_nul_and_control_bytes_in_text_fields() {
        for row in ["a\0b.c\t0x100\t4\tdata\t4", "u\x7f.c\t0x100\t4\tdata\t4"] {
            assert!(error(row).contains("control byte"));
        }
    }

    #[test]
    fn rejects_allocations_without_compatible_pdb_symbols() {
        assert!(error("u.c\t0x101\t4\tdata\t4").contains("PDB data symbol"));
        assert!(error("u.c\t0x100\t4\trdata\t4").contains("PDB data symbol"));
    }

    #[test]
    fn rejects_duplicate_rvas() {
        let text = format!("{HEADER_TEXT}one.c\t0x100\t4\tdata\t4\ntwo.c\t0x100\t4\tdata\t4\n");
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
        let text = format!("{HEADER_TEXT}one.c\t0x100\t0x20\tdata\t4\ntwo.c\t0x110\t4\tdata\t4\n");
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
        let text = format!("{HEADER_TEXT}one.c\t0x100\t0x20\tdata\t4\ntwo.c\t0x120\t4\tdata\t4\n");
        assert_eq!(parse(&text).unwrap().definitions().len(), 2);
    }

    #[test]
    fn rejects_extent_overflow_and_zero_size() {
        let overflow = format!("u.c\t{}\t2\tdata\t4", usize::MAX);
        assert!(error(&overflow).contains("overflows"));
        assert!(error("u.c\t0x100\t0\tdata\t4").contains("non-zero"));
    }

    #[test]
    fn rejects_zero_and_non_power_of_two_alignment() {
        assert!(error("u.c\t0x100\t4\tdata\t0").contains("power of two"));
        assert!(error("u.c\t0x100\t4\tdata\t3").contains("power of two"));
    }

    #[test]
    fn resolves_interior_owner_and_addend_at_exact_boundaries() {
        let parsed = parse(&format!(
            "{HEADER_TEXT}v.c\t0x140\t0x10\tdata\t4\nu.c\t0x100\t0x20\tdata\t4\n"
        ))
        .unwrap();
        assert_eq!(parsed.definitions()[0].symbol_name.as_bytes(), b"table");
        assert_eq!(parsed.definitions()[1].symbol_name.as_bytes(), b"later");
        assert!(parsed.owner_and_addend_for_rva(0xff).is_none());
        let (owner, addend) = parsed.owner_and_addend_for_rva(0x100).unwrap();
        assert_eq!(owner.symbol_name.as_bytes(), b"table");
        assert_eq!(addend, 0);
        assert_eq!(parsed.owner_and_addend_for_rva(0x10f).unwrap().1, 0xf);
        assert_eq!(parsed.owner_and_addend_for_rva(0x11f).unwrap().1, 0x1f);
        assert!(parsed.owner_and_addend_for_rva(0x120).is_none());
        assert!(parsed.owner_and_addend_for_rva(0x13f).is_none());
        assert_eq!(parsed.owner_and_addend_for_rva(0x140).unwrap().1, 0);
        assert_eq!(parsed.owner_and_addend_for_rva(0x14f).unwrap().1, 0xf);
        assert!(parsed.owner_and_addend_for_rva(0x150).is_none());
    }
}
