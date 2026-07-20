use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};
use pdb2::RawString;

use crate::pdb_symbols::{FunctionRelocationField, PdbSymbols};

use std::collections::BTreeMap;
use std::path::Path;

const HEADER: &[u8] = b"function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences";

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    function_rva: &'a [u8],
    target_rva: &'a [u8],
    site_rva: &'a [u8],
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
        terminated(field, tag(&b"\t"[..])),
        field,
    )
        .parse(input)?;
    Ok((
        input,
        ManifestRow {
            function_rva: fields.0,
            target_rva: fields.1,
            site_rva: fields.2,
            owner: fields.3,
            addend: fields.4,
            occurrences: fields.5,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RelocAliasKey {
    function_rva: usize,
    target_rva: usize,
    site_rva: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocAlias {
    pub function_rva: usize,
    pub target_rva: usize,
    pub site_rva: Option<usize>,
    pub owner: RawString<'static>,
    pub addend: u32,
    pub occurrences: usize,
}

impl RelocAlias {
    fn key(self) -> RelocAliasKey {
        RelocAliasKey {
            function_rva: self.function_rva,
            target_rva: self.target_rva,
            site_rva: self.site_rva,
        }
    }
}

#[derive(Default)]
pub struct RelocAliasObservations {
    counts: BTreeMap<RelocAliasKey, usize>,
}

#[derive(Default)]
pub struct RelocAliasManifest {
    aliases: BTreeMap<RelocAliasKey, RelocAlias>,
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
                    "{}:{}: expected exactly six tab-separated columns",
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
            let site_rva = match row.site_rva {
                b"*" => None,
                value => Some(parse_number(value)?),
            };
            let addend = u32::try_from(parse_number(row.addend)?)?;
            let occurrences = parse_number(row.occurrences)?;
            if occurrences == 0 {
                anyhow::bail!(
                    "{}:{}: occurrence count must be non-zero",
                    path.display(),
                    line_number
                );
            }
            if site_rva.is_some() && occurrences != 1 {
                anyhow::bail!(
                    "{}:{}: exact relocation site must have exactly one occurrence",
                    path.display(),
                    line_number
                );
            }
            let owner: &'static [u8] = row.owner.to_vec().leak();
            let alias = RelocAlias {
                function_rva,
                target_rva,
                site_rva,
                owner: RawString::from(owner),
                addend,
                occurrences,
            };
            if aliases.insert(alias.key(), alias).is_some() {
                let site = site_rva
                    .map(|rva| format!("{rva:#x}"))
                    .unwrap_or_else(|| "*".to_string());
                anyhow::bail!(
                    "{}:{}: duplicate relocation function/target/site RVAs {function_rva:#x}/{target_rva:#x}/{site}",
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

    fn select(
        &self,
        function_rva: usize,
        target_rva: usize,
        site_rva: usize,
    ) -> Option<(RelocAliasKey, RelocAlias)> {
        let exact = RelocAliasKey {
            function_rva,
            target_rva,
            site_rva: Some(site_rva),
        };
        let wildcard = RelocAliasKey {
            function_rva,
            target_rva,
            site_rva: None,
        };
        self.aliases
            .get(&exact)
            .map(|alias| (exact, *alias))
            .or_else(|| self.aliases.get(&wildcard).map(|alias| (wildcard, *alias)))
    }

    pub fn resolve(
        &self,
        function_rva: usize,
        target_rva: usize,
        site_rva: usize,
        observed: &mut RelocAliasObservations,
    ) -> Option<RelocAlias> {
        let (key, alias) = self.select(function_rva, target_rva, site_rva)?;
        *observed.counts.entry(key).or_default() += 1;
        Some(alias)
    }

    pub fn resolve_function_alias(
        &self,
        function_rva: usize,
        target_rva: usize,
        site_rva: usize,
        overloads: &[RawString<'static>],
        observed: &mut RelocAliasObservations,
    ) -> anyhow::Result<Option<RawString<'static>>> {
        let Some(alias) = self.resolve(function_rva, target_rva, site_rva, observed) else {
            return Ok(None);
        };
        if alias.addend != 0 {
            anyhow::bail!(
                "function relocation alias {function_rva:#x}/{target_rva:#x}/{site_rva:#x} has non-zero addend {:#x}",
                alias.addend
            );
        }
        if !overloads.contains(&alias.owner) {
            anyhow::bail!(
                "function relocation alias owner {} is absent at target RVA {target_rva:#x}",
                alias.owner
            );
        }
        Ok(Some(alias.owner))
    }

    pub fn validate_site_membership(&self, symbols: &PdbSymbols) -> anyhow::Result<()> {
        for alias in self.aliases.values() {
            let Some(site_rva) = alias.site_rva else {
                continue;
            };
            match symbols.relocation_field_in_function(alias.function_rva, site_rva) {
                FunctionRelocationField::Within { .. } => {}
                FunctionRelocationField::MissingFunction => anyhow::bail!(
                    "relocation alias exact site {site_rva:#x} names missing function {:#x}",
                    alias.function_rva
                ),
                FunctionRelocationField::UnknownExtent => anyhow::bail!(
                    "relocation alias exact site {site_rva:#x} names function {:#x} without a Procedure/Thunk extent",
                    alias.function_rva
                ),
                FunctionRelocationField::OutsideExtent => anyhow::bail!(
                    "relocation alias exact site field {site_rva:#x}..{:#x} is outside function {:#x}",
                    site_rva.saturating_add(std::mem::size_of::<u32>()),
                    alias.function_rva
                ),
                FunctionRelocationField::FieldOverflow => {
                    anyhow::bail!("relocation alias exact site {site_rva:#x} overflows RVA")
                }
            }
        }
        Ok(())
    }

    pub fn validate_occurrences(&self, observed: &RelocAliasObservations) -> anyhow::Result<()> {
        for (key, alias) in &self.aliases {
            let count = observed.counts.get(key).copied().unwrap_or(0);
            if count != alias.occurrences {
                let site = key
                    .site_rva
                    .map(|rva| format!("{rva:#x}"))
                    .unwrap_or_else(|| "*".to_string());
                anyhow::bail!(
                    "relocation alias {:#x}/{:#x}/{site} expected {} occurrence(s), observed {count}",
                    key.function_rva,
                    key.target_rva,
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

    const HEADER_TEXT: &str = "function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences\n";

    #[test]
    fn parses_wrapping_addend_and_crlf() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences\r\n\
              0x4a061\t0xf5180\t*\t?data@@3PAUitem@@A\t0xfffffff8\t1",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        let mut observed = RelocAliasObservations::default();
        assert_eq!(
            manifest.resolve(0x4a061, 0xf5180, 0x4a080, &mut observed),
            Some(RelocAlias {
                function_rva: 0x4a061,
                target_rva: 0xf5180,
                site_rva: None,
                owner: RawString::from(&b"?data@@3PAUitem@@A"[..]),
                addend: 0xfffffff8,
                occurrences: 1,
            })
        );
    }

    #[test]
    fn rejects_duplicate_keys_and_wrong_columns() {
        let duplicate = format!(
            "{HEADER_TEXT}0x2000\t0x1000\t0x2010\ta\t0\t1\n\
             0x2000\t0x1000\t0x2010\tb\t0\t1\n"
        );
        assert!(RelocAliasManifest::parse(duplicate.as_bytes(), Path::new("aliases.tsv")).is_err());
        let extra = format!("{HEADER_TEXT}0x2000\t0x1000\t*\ta\t0\t1\textra\n");
        assert!(RelocAliasManifest::parse(extra.as_bytes(), Path::new("aliases.tsv")).is_err());
    }

    #[test]
    fn rejects_non_unit_exact_site_occurrences() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2010\ta\t0\t2\n");
        assert!(RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).is_err());
    }

    #[test]
    fn validates_exact_site_membership() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x3010\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"a"[..]), Some(0x20))
            .unwrap();
        symbols
            .add_function_at_rva(0x3000, RawString::from(&b"b"[..]), Some(0x20))
            .unwrap();
        assert!(manifest.validate_site_membership(&symbols).is_err());
    }

    #[test]
    fn rejects_exact_site_field_crossing_next_function() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2ffe\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"a"[..]), Some(0x1000))
            .unwrap();
        symbols
            .add_function_at_rva(0x3000, RawString::from(&b"b"[..]), Some(0x20))
            .unwrap();
        assert!(manifest.validate_site_membership(&symbols).is_err());
    }

    #[test]
    fn exact_site_requires_a_procedure_extent() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2000\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"a"[..]), None)
            .unwrap();
        let error = manifest
            .validate_site_membership(&symbols)
            .unwrap_err()
            .to_string();
        assert!(error.contains("without a Procedure/Thunk extent"));
    }

    #[test]
    fn exact_site_requires_an_existing_function() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2000\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let error = manifest
            .validate_site_membership(&PdbSymbols::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("names missing function 0x2000"));
    }

    #[test]
    fn exact_site_after_final_function_is_rejected() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2010\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"a"[..]), Some(0x10))
            .unwrap();
        assert!(manifest.validate_site_membership(&symbols).is_err());
    }

    #[test]
    fn exact_site_field_may_end_at_function_extent() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x200c\ta\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut symbols = PdbSymbols::default();
        symbols
            .add_function_at_rva(0x2000, RawString::from(&b"a"[..]), Some(0x10))
            .unwrap();
        assert!(manifest.validate_site_membership(&symbols).is_ok());
    }

    #[test]
    fn exact_site_overrides_wildcard_for_mixed_midi_end_sentinels() {
        let text = format!(
            "{HEADER_TEXT}0xd3910\t0x134de0\t*\t?hSequence@@3PAPAU_SEQUENCE@@A\t0\t5\n\
             0xd3910\t0x134de0\t0xd3aa5\t?pMIDIWrap@@3PAPAVMIDIWrap@@A\t0xf0\t1\n"
        );
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut observed = RelocAliasObservations::default();
        for site_rva in [0xd398a, 0xd39aa, 0xd39d9, 0xd39ee, 0xd3a32] {
            assert_eq!(
                manifest
                    .resolve(0xd3910, 0x134de0, site_rva, &mut observed)
                    .unwrap()
                    .owner,
                RawString::from(&b"?hSequence@@3PAPAU_SEQUENCE@@A"[..])
            );
        }
        let exact = manifest
            .resolve(0xd3910, 0x134de0, 0xd3aa5, &mut observed)
            .unwrap();
        assert_eq!(
            exact.owner,
            RawString::from(&b"?pMIDIWrap@@3PAPAVMIDIWrap@@A"[..])
        );
        assert_eq!(exact.addend, 0xf0);
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }

    #[test]
    fn validates_observed_occurrence_count_per_selected_row() {
        let text = format!(
            "{HEADER_TEXT}0x2000\t0x1000\t*\ta\t0\t2\n\
             0x2000\t0x1000\t0x2010\tb\t0\t1\n"
        );
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut observed = RelocAliasObservations::default();
        manifest.resolve(0x2000, 0x1000, 0x2008, &mut observed);
        manifest.resolve(0x2000, 0x1000, 0x2010, &mut observed);
        assert!(manifest.validate_occurrences(&observed).is_err());
    }

    #[test]
    fn resolves_reviewed_function_alias_by_exact_site() {
        let text = format!("{HEADER_TEXT}0x4a0f0\t0xe0130\t0x4a120\t__write\t0\t1\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let overloads = [
            RawString::from(&b"__write"[..]),
            RawString::from(&b"_write"[..]),
        ];
        let mut observed = RelocAliasObservations::default();
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, 0x4a120, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(&b"__write"[..]))
        );
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }
}
