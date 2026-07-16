use pdb2::RawString;

use std::collections::BTreeMap;
use std::path::Path;

const HEADER: &[u8] = b"function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences\tprovenance";
const LEGACY_HEADER: &[u8] = b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance";

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
        let mut aliases = BTreeMap::new();
        let mut column_count = None;
        for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            let line_number = line_index + 1;
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            if column_count.is_none() {
                column_count = Some(match line {
                    HEADER => 7,
                    LEGACY_HEADER => 6,
                    _ => {
                        anyhow::bail!(
                            "{}:{}: invalid relocation alias manifest header",
                            path.display(),
                            line_number
                        )
                    }
                });
                continue;
            }
            let columns = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            let expected_columns = column_count.unwrap();
            if columns.len() != expected_columns {
                anyhow::bail!(
                    "{}:{}: expected exactly {expected_columns} tab-separated columns",
                    path.display(),
                    line_number
                );
            }

            let function_rva = parse_number(columns[0])?;
            let target_rva = parse_number(columns[1])?;
            let (site_rva, owner_column, addend_column, occurrences_column, provenance_column) =
                if expected_columns == 7 {
                    let site_rva = match columns[2] {
                        b"*" => None,
                        value => Some(parse_number(value)?),
                    };
                    (site_rva, 3, 4, 5, 6)
                } else {
                    (None, 2, 3, 4, 5)
                };
            if columns[owner_column].is_empty()
                || columns[owner_column].iter().any(|byte| *byte < 0x20)
            {
                anyhow::bail!(
                    "{}:{}: invalid relocation owner",
                    path.display(),
                    line_number
                );
            }
            let addend = u32::try_from(parse_number(columns[addend_column])?)?;
            let occurrences = parse_number(columns[occurrences_column])?;
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
            if columns[provenance_column].is_empty()
                || columns[provenance_column].iter().any(|byte| *byte < 0x20)
            {
                anyhow::bail!("{}:{}: invalid provenance", path.display(), line_number);
            }
            let owner: &'static [u8] = columns[owner_column].to_vec().leak();
            let alias = RelocAlias {
                function_rva,
                target_rva,
                site_rva,
                owner: owner.into(),
                addend,
                occurrences,
            };
            if aliases.insert(alias.key(), alias).is_some() {
                let site = site_rva
                    .map(|rva| format!("{rva:#x}"))
                    .unwrap_or_else(|| "*".to_string());
                anyhow::bail!(
                    "{}:{}: duplicate relocation function/target/site RVA {function_rva:#x}/{target_rva:#x}/{site}",
                    path.display(),
                    line_number
                );
            }
        }
        if column_count.is_none() {
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

    pub fn validate_site_membership(
        &self,
        functions: &BTreeMap<usize, Vec<RawString<'static>>>,
    ) -> anyhow::Result<()> {
        for alias in self.aliases.values() {
            let Some(site_rva) = alias.site_rva else {
                continue;
            };
            let containing_function = functions
                .range(..=site_rva)
                .next_back()
                .map(|(rva, _)| *rva);
            if containing_function != Some(alias.function_rva) {
                anyhow::bail!(
                    "relocation alias exact site {site_rva:#x} is not in function {:#x}",
                    alias.function_rva
                );
            }
            if let Some((next_function_rva, _)) = functions
                .range(alias.function_rva.saturating_add(1)..)
                .next()
            {
                let site_end = site_rva
                    .checked_add(std::mem::size_of::<u32>())
                    .ok_or_else(|| anyhow::anyhow!("relocation alias exact site overflows RVA"))?;
                if site_end > *next_function_rva {
                    anyhow::bail!(
                        "relocation alias exact site {site_rva:#x} crosses function {:#x} boundary",
                        alias.function_rva
                    );
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

fn parse_number(bytes: &[u8]) -> anyhow::Result<usize> {
    let text = std::str::from_utf8(bytes)?;
    let value = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
    Ok(match value {
        Some(hex) => usize::from_str_radix(hex, 16)?,
        None => text.parse()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TEXT: &str =
        "function_rva\ttarget_rva\tsite_rva\towner\taddend\toccurrences\tprovenance\n";

    #[test]
    fn parses_signed_addend_encoding() {
        let text = format!(
            "{HEADER_TEXT}0x0004a061\t0x000f5180\t*\t?data@@3PAUitem@@A\t0xfffffff8\t1\treviewed\n"
        );
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let mut observed = RelocAliasObservations::default();
        assert_eq!(
            manifest.resolve(0x4a061, 0xf5180, 0x4a080, &mut observed),
            Some(RelocAlias {
                function_rva: 0x4a061,
                target_rva: 0xf5180,
                site_rva: None,
                owner: b"?data@@3PAUitem@@A".as_slice().into(),
                addend: 0xfffffff8,
                occurrences: 1,
            })
        );
    }

    #[test]
    fn accepts_legacy_wildcard_schema() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance\n\
              0x2000\t0x1000\ta\t0\t1\treviewed\n",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        assert_eq!(manifest.aliases.values().next().unwrap().site_rva, None);
    }

    #[test]
    fn rejects_duplicate_function_target_site() {
        let text = format!(
            "{HEADER_TEXT}0x2000\t0x1000\t0x2010\ta\t0\t1\treviewed\n\
             0x2000\t0x1000\t0x2010\tb\t0\t1\treviewed\n"
        );
        assert!(RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).is_err());
    }

    #[test]
    fn rejects_non_unit_exact_site_occurrences() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2010\ta\t0\t2\treviewed\n");
        assert!(RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).is_err());
    }

    #[test]
    fn validates_exact_site_membership() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x3010\ta\t0\t1\treviewed\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let functions = BTreeMap::from([
            (0x2000, vec![RawString::from(b"a".as_slice())]),
            (0x3000, vec![RawString::from(b"b".as_slice())]),
        ]);
        assert!(manifest.validate_site_membership(&functions).is_err());
    }

    #[test]
    fn rejects_exact_site_field_crossing_next_function() {
        let text = format!("{HEADER_TEXT}0x2000\t0x1000\t0x2ffe\ta\t0\t1\treviewed\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let functions = BTreeMap::from([
            (0x2000, vec![RawString::from(b"a".as_slice())]),
            (0x3000, vec![RawString::from(b"b".as_slice())]),
        ]);
        assert!(manifest.validate_site_membership(&functions).is_err());
    }

    #[test]
    fn exact_site_overrides_wildcard_for_mixed_midi_end_sentinels() {
        let text = format!(
            "{HEADER_TEXT}0xd3910\t0x134de0\t*\t?hSequence@@3PAPAU_SEQUENCE@@A\t0\t5\treviewed\n\
             0xd3910\t0x134de0\t0xd3aa5\t?pMIDIWrap@@3PAPAVMIDIWrap@@A\t0xf0\t1\treviewed\n"
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
                RawString::from(b"?hSequence@@3PAPAU_SEQUENCE@@A".as_slice())
            );
        }
        let exact = manifest
            .resolve(0xd3910, 0x134de0, 0xd3aa5, &mut observed)
            .unwrap();
        assert_eq!(
            exact.owner,
            RawString::from(b"?pMIDIWrap@@3PAPAVMIDIWrap@@A".as_slice())
        );
        assert_eq!(exact.addend, 0xf0);
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }

    #[test]
    fn validates_observed_occurrence_count_per_selected_row() {
        let text = format!(
            "{HEADER_TEXT}0x2000\t0x1000\t*\ta\t0\t2\treviewed\n\
             0x2000\t0x1000\t0x2010\tb\t0\t1\treviewed\n"
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
        let text =
            format!("{HEADER_TEXT}0x4a0f0\t0xe0130\t0x4a120\t__write\t0\t1\treviewed-crt-alias\n");
        let manifest =
            RelocAliasManifest::parse(text.as_bytes(), Path::new("aliases.tsv")).unwrap();
        let overloads = [
            RawString::from(b"__write".as_slice()),
            RawString::from(b"_write".as_slice()),
        ];
        let mut observed = RelocAliasObservations::default();
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, 0x4a120, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(b"__write".as_slice()))
        );
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }
}
