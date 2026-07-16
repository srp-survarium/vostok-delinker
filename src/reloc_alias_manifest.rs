use pdb2::RawString;

use std::collections::BTreeMap;
use std::path::Path;

const HEADER: &[u8] = b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance";

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
        let mut aliases = BTreeMap::new();
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
                        "{}:{}: invalid relocation alias manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            let columns = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            if columns.len() != 6 {
                anyhow::bail!(
                    "{}:{}: expected exactly six tab-separated columns",
                    path.display(),
                    line_number
                );
            }
            if columns[2].is_empty() || columns[2].iter().any(|byte| *byte < 0x20) {
                anyhow::bail!(
                    "{}:{}: invalid relocation owner",
                    path.display(),
                    line_number
                );
            }
            let function_rva = parse_number(columns[0])?;
            let target_rva = parse_number(columns[1])?;
            let addend = u32::try_from(parse_number(columns[3])?)?;
            let occurrences = parse_number(columns[4])?;
            if occurrences == 0 {
                anyhow::bail!(
                    "{}:{}: occurrence count must be non-zero",
                    path.display(),
                    line_number
                );
            }
            if columns[5].is_empty() || columns[5].iter().any(|byte| *byte < 0x20) {
                anyhow::bail!("{}:{}: invalid provenance", path.display(), line_number);
            }
            let owner: &'static [u8] = columns[2].to_vec().leak();
            let alias = RelocAlias {
                function_rva,
                target_rva,
                owner: owner.into(),
                addend,
                occurrences,
            };
            if aliases.insert((function_rva, target_rva), alias).is_some() {
                anyhow::bail!(
                    "{}:{}: duplicate relocation function/target RVA {function_rva:#x}/{target_rva:#x}",
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
        if !overloads.iter().any(|name| *name == alias.owner) {
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

    #[test]
    fn parses_signed_addend_encoding() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance\n\
              0x0004a061\t0x000f5180\t?data@@3PAUitem@@A\t0xfffffff8\t1\treviewed\n",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        assert_eq!(
            manifest.get(0x4a061, 0xf5180),
            Some(RelocAlias {
                function_rva: 0x4a061,
                target_rva: 0xf5180,
                owner: b"?data@@3PAUitem@@A".as_slice().into(),
                addend: 0xfffffff8,
                occurrences: 1,
            })
        );
    }

    #[test]
    fn rejects_duplicate_targets() {
        let result = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance\n\
              0x2000\t0x1000\ta\t0\t1\treviewed\n\
              0x2000\t0x1000\tb\t0\t1\treviewed\n",
            Path::new("aliases.tsv"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn validates_observed_occurrence_count() {
        let manifest = RelocAliasManifest::parse(
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance\n\
              0x2000\t0x1000\ta\t0\t2\treviewed\n",
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
            b"function_rva\ttarget_rva\towner\taddend\toccurrences\tprovenance\n\
              0x4a0f0\t0xe0130\t__write\t0\t2\treviewed-crt-alias\n",
            Path::new("aliases.tsv"),
        )
        .unwrap();
        let overloads = [
            RawString::from(b"__write".as_slice()),
            RawString::from(b"_write".as_slice()),
        ];
        let mut observed = BTreeMap::new();
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(b"__write".as_slice()))
        );
        assert_eq!(
            manifest
                .resolve_function_alias(0x4a0f0, 0xe0130, &overloads, &mut observed)
                .unwrap(),
            Some(RawString::from(b"__write".as_slice()))
        );
        assert!(manifest.validate_occurrences(&observed).is_ok());
    }
}
