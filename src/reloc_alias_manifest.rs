use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};
use pdb2::RawString;

use std::collections::BTreeMap;
use std::path::Path;

const HEADER: &[u8] = b"function_rva\ttarget_rva\towner\taddend\toccurrences";

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    function_rva: &'a [u8],
    target_rva: &'a [u8],
    owner: &'a [u8],
    addend: &'a [u8],
    occurrences: &'a [u8],
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
        field,
    )
        .parse(input)?;
    Ok((
        input,
        ManifestRow {
            function_rva: fields.0,
            target_rva: fields.1,
            owner: fields.2,
            addend: fields.3,
            occurrences: fields.4,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocAlias {
    pub function_rva: usize,
    pub target_rva: usize,
    pub owner: RawString<'static>,
    pub addend: u32,
    pub occurrences: usize,
}

#[derive(Default)]
pub struct RelocAliasManifest {
    aliases: BTreeMap<(usize, usize), RelocAlias>,
}

impl RelocAliasManifest {
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
        let mut aliases = BTreeMap::new();
        let mut saw_header = false;

        for (line_index, line) in lines.into_iter().enumerate() {
            let line_number = line_index + 1;
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            if !saw_header {
                if line != HEADER {
                    anyhow::bail!(
                        "{}:{}: invalid relocation alias manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            if line == HEADER {
                anyhow::bail!(
                    "{}:{}: duplicate relocation alias manifest header",
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
            if row.owner.is_empty() || row.owner.iter().any(|byte| byte.is_ascii_control()) {
                anyhow::bail!(
                    "{}:{}: relocation owner must be non-empty printable bytes",
                    path.display(),
                    line_number
                );
            }
            let function_rva = parse_number(row.function_rva)?;
            let target_rva = parse_number(row.target_rva)?;
            let addend = u32::try_from(parse_number(row.addend)?)?;
            let occurrences = parse_number(row.occurrences)?;
            if occurrences == 0 {
                anyhow::bail!(
                    "{}:{}: occurrence count must be non-zero",
                    path.display(),
                    line_number
                );
            }
            let owner: &'static [u8] = row.owner.to_vec().leak();
            let alias = RelocAlias {
                function_rva,
                target_rva,
                owner: RawString::from(owner),
                addend,
                occurrences,
            };
            if aliases.insert((function_rva, target_rva), alias).is_some() {
                anyhow::bail!(
                    "{}:{}: duplicate relocation function/target RVAs {function_rva:#x}/{target_rva:#x}",
                    path.display(),
                    line_number
                );
            }
        }
        if !saw_header {
            anyhow::bail!(
                "{}: missing relocation alias manifest header",
                path.display()
            );
        }
        Ok(Self { aliases })
    }

    pub fn get(&self, function_rva: usize, target_rva: usize) -> Option<RelocAlias> {
        self.aliases.get(&(function_rva, target_rva)).copied()
    }

    pub fn resolve_function_alias(
        &self,
        function_rva: usize,
        target_rva: usize,
        overloads: &[RawString<'static>],
        observed: &mut BTreeMap<(usize, usize), usize>,
    ) -> anyhow::Result<Option<RawString<'static>>> {
        let Some(alias) = self.get(function_rva, target_rva) else {
            return Ok(None);
        };
        if alias.addend != 0 {
            anyhow::bail!(
                "function relocation alias {function_rva:#x}/{target_rva:#x} has non-zero addend {:#x}",
                alias.addend
            );
        }
        if !overloads.contains(&alias.owner) {
            anyhow::bail!(
                "function relocation alias owner {} is absent at target RVA {target_rva:#x}",
                alias.owner
            );
        }
        *observed.entry((function_rva, target_rva)).or_default() += 1;
        Ok(Some(alias.owner))
    }

    pub fn validate_occurrences(
        &self,
        observed: &BTreeMap<(usize, usize), usize>,
    ) -> anyhow::Result<()> {
        for (key, alias) in &self.aliases {
            let count = observed.get(key).copied().unwrap_or(0);
            if count != alias.occurrences {
                anyhow::bail!(
                    "relocation alias {:#x}/{:#x} expected {} occurrence(s), observed {count}",
                    key.0,
                    key.1,
                    alias.occurrences
                );
            }
        }
        Ok(())
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

    #[test]
    fn parses_wrapping_addend_and_crlf() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\r\n\
              0x4a061\t0xf5180\t?data@@3PAUitem@@A\t0xfffffff8\t1",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        assert_eq!(
            manifest.get(0x4a061, 0xf5180),
            Some(RelocAlias {
                function_rva: 0x4a061,
                target_rva: 0xf5180,
                owner: RawString::from(&b"?data@@3PAUitem@@A"[..]),
                addend: 0xfffffff8,
                occurrences: 1,
            })
        );
    }

    #[test]
    fn rejects_duplicate_keys_and_wrong_columns() {
        let duplicate = b"function_rva\ttarget_rva\towner\taddend\toccurrences\n\
            0x2000\t0x1000\ta\t0\t1\n\
            0x2000\t0x1000\tb\t0\t1\n";
        assert!(RelocAliasManifest::parse(duplicate, Path::new("aliases.tsv")).is_err());
        let extra = b"function_rva\ttarget_rva\towner\taddend\toccurrences\n\
            0x2000\t0x1000\ta\t0\t1\textra\n";
        assert!(RelocAliasManifest::parse(extra, Path::new("aliases.tsv")).is_err());
    }

    #[test]
    fn validates_observed_occurrence_count() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\n\
              0x2000\t0x1000\ta\t0\t2\n",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        assert!(
            manifest
                .validate_occurrences(&BTreeMap::from([((0x2000, 0x1000), 2)]))
                .is_ok()
        );
        assert!(manifest.validate_occurrences(&BTreeMap::new()).is_err());
    }

    #[test]
    fn resolves_reviewed_function_alias() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\n\
              0x4a0f0\t0xe0130\t__write\t0\t2\n",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        let overloads = [
            RawString::from(&b"__write"[..]),
            RawString::from(&b"_write"[..]),
        ];
        let mut observed = BTreeMap::new();
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(&b"__write"[..]))
        );
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(&b"__write"[..]))
        );
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }
}
