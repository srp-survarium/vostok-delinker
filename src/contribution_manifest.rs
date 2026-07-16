use std::path::Path;

const HEADER: &[u8] = b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContributionStorage {
    Text,
    Rdata,
    Data,
    Bss,
}

#[derive(Clone, Copy, Debug)]
struct Contribution {
    object: &'static [u8],
    storage: ContributionStorage,
    rva: usize,
    size: usize,
}

#[derive(Default)]
pub struct ContributionManifest {
    contributions: Vec<Contribution>,
}

impl ContributionManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let mut contributions = Vec::new();
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
                        "{}:{}: invalid contribution manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            let columns = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
            if columns.len() != 7 {
                anyhow::bail!(
                    "{}:{}: expected exactly seven tab-separated columns",
                    path.display(),
                    line_number
                );
            }
            for (field, value) in [
                ("object", columns[0]),
                ("section", columns[5]),
                ("provenance", columns[6]),
            ] {
                validate_text(path, line_number, field, value)?;
                if value.is_empty() {
                    anyhow::bail!(
                        "{}:{}: {} must be non-empty",
                        path.display(),
                        line_number,
                        field
                    );
                }
            }
            let object = std::str::from_utf8(columns[0])?.replace('/', "\\");
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
            let storage = match columns[1] {
                b"text" => ContributionStorage::Text,
                b"rdata" => ContributionStorage::Rdata,
                b"data" => ContributionStorage::Data,
                b"bss" => ContributionStorage::Bss,
                value => anyhow::bail!(
                    "{}:{}: unsupported storage {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(value)
                ),
            };
            let expected_section = match storage {
                ContributionStorage::Text => b".text".as_slice(),
                ContributionStorage::Rdata => b".rdata".as_slice(),
                ContributionStorage::Data | ContributionStorage::Bss => b".data".as_slice(),
            };
            if columns[5] != expected_section {
                anyhow::bail!(
                    "{}:{}: storage does not match PE section",
                    path.display(),
                    line_number
                );
            }
            let rva = parse_number(columns[2])?;
            let size = parse_number(columns[3])?;
            if size == 0 || rva.checked_add(size).is_none() {
                anyhow::bail!(
                    "{}:{}: contribution extent must be non-empty and non-overflowing",
                    path.display(),
                    line_number
                );
            }
            let segment = parse_number(columns[4])?;
            if segment == 0 || segment > usize::from(u16::MAX) {
                anyhow::bail!(
                    "{}:{}: segment must fit a non-zero u16",
                    path.display(),
                    line_number
                );
            }
            contributions.push(Contribution {
                object: object.into_bytes().leak(),
                storage,
                rva,
                size,
            });
        }
        if !saw_header {
            anyhow::bail!("{}: missing contribution manifest header", path.display());
        }
        contributions.sort_by_key(|contribution| contribution.rva);
        for pair in contributions.windows(2) {
            if pair[0].rva.checked_add(pair[0].size).unwrap() > pair[1].rva {
                anyhow::bail!("overlapping contribution manifest intervals");
            }
        }
        Ok(Self { contributions })
    }

    pub fn same_owner(
        &self,
        storage: ContributionStorage,
        symbol_rva: usize,
        target_rva: usize,
    ) -> bool {
        let Some(target_owner) = self.owner_for_rva(storage, target_rva) else {
            return true;
        };
        self.owner_for_rva(storage, symbol_rva) == Some(target_owner)
    }

    pub fn storage_for_rva(&self, rva: usize) -> Option<ContributionStorage> {
        self.contributions.iter().find_map(|contribution| {
            if contribution.rva <= rva && rva - contribution.rva < contribution.size {
                Some(contribution.storage)
            } else {
                None
            }
        })
    }

    pub fn owner_for_rva(&self, storage: ContributionStorage, rva: usize) -> Option<&'static [u8]> {
        self.contributions.iter().find_map(|contribution| {
            if contribution.storage == storage
                && contribution.rva <= rva
                && rva - contribution.rva < contribution.size
            {
                Some(contribution.object)
            } else {
                None
            }
        })
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

    const MANIFEST: &[u8] = b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\ONE.c\trdata\t0x100\t0x20\t2\t.rdata\ttest\n\
SOURCE\\TWO.c\trdata\t0x120\t0x20\t2\t.rdata\ttest\n\
SOURCE\\ONE.c\tdata\t0x200\t0x10\t3\t.data\ttest\n\
SOURCE\\ONE.c\tbss\t0x300\t0x10\t3\t.data\ttest\n";

    #[test]
    fn constrains_symbols_to_target_compiland() {
        let manifest = ContributionManifest::parse(MANIFEST, Path::new("test.tsv")).unwrap();
        assert!(manifest.same_owner(ContributionStorage::Rdata, 0x101, 0x11f));
        assert!(!manifest.same_owner(ContributionStorage::Rdata, 0x101, 0x120));
        assert!(manifest.same_owner(ContributionStorage::Rdata, 0x120, 0x13f));
        assert!(manifest.same_owner(ContributionStorage::Rdata, 0x99, 0x99));
    }

    #[test]
    fn storage_classes_do_not_alias() {
        let manifest = ContributionManifest::parse(MANIFEST, Path::new("test.tsv")).unwrap();
        assert!(!manifest.same_owner(ContributionStorage::Bss, 0x200, 0x300));
        assert_eq!(
            manifest.storage_for_rva(0x30f),
            Some(ContributionStorage::Bss)
        );
    }

    #[test]
    fn rejects_overlapping_intervals() {
        let bytes = [
            MANIFEST,
            b"SOURCE\\BAD.c\trdata\t0x110\t0x20\t2\t.rdata\ttest\n",
        ]
        .concat();
        assert!(ContributionManifest::parse(&bytes, Path::new("test.tsv")).is_err());
    }

    #[test]
    fn rejects_storage_section_mismatch() {
        let bytes = b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\tbss\t0x100\t0x20\t2\t.rdata\ttest\n";
        assert!(ContributionManifest::parse(bytes, Path::new("test.tsv")).is_err());
    }
}
