use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};

use std::path::Path;

const HEADER: &[u8] = b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance";

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    object: &'a [u8],
    storage: &'a [u8],
    rva: &'a [u8],
    size: &'a [u8],
    segment: &'a [u8],
    section: &'a [u8],
    provenance: &'a [u8],
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
        field,
    )
        .parse(input)?;
    Ok((
        input,
        ManifestRow {
            object: fields.0,
            storage: fields.1,
            rva: fields.2,
            size: fields.3,
            segment: fields.4,
            section: fields.5,
            provenance: fields.6,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContributionStorage {
    Text,
    Rdata,
    Data,
    Bss,
}

impl ContributionStorage {
    /// The linked PE section a contribution of this storage must live in.
    ///
    /// `data` and `bss` share one PE section: the linker places a compiland's
    /// initialized bytes and its loader-zeroed tail in `.data`, and only the
    /// section's raw size separates them.
    fn pe_section(self) -> &'static [u8] {
        match self {
            Self::Text => b".text",
            Self::Rdata => b".rdata",
            Self::Data | Self::Bss => b".data",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Contribution {
    object: &'static [u8],
    storage: ContributionStorage,
    rva: usize,
    size: usize,
}

/// Per-compiland contribution intervals of the linked image.
///
/// Sorted by RVA and free of overlap, so one address resolves to at most one
/// contribution.
#[derive(Debug, Default)]
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
        let (_, lines) = all_consuming(manifest_lines)
            .parse(bytes)
            .map_err(|_| anyhow::anyhow!("{}: invalid line ending", path.display()))?;
        let mut contributions = Vec::new();
        let mut saw_header = false;

        for (line_index, line) in lines.into_iter().enumerate() {
            let line_number = line_index + 1;
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

            let (_, row) = all_consuming(manifest_row).parse(line).map_err(|_| {
                anyhow::anyhow!(
                    "{}:{}: expected exactly seven tab-separated columns",
                    path.display(),
                    line_number
                )
            })?;

            for (name, value) in [("object", row.object), ("provenance", row.provenance)] {
                if value.is_empty() {
                    anyhow::bail!(
                        "{}:{}: {} must be non-empty",
                        path.display(),
                        line_number,
                        name
                    );
                }
                if value.iter().any(|byte| byte.is_ascii_control()) {
                    anyhow::bail!(
                        "{}:{}: {} contains a control byte",
                        path.display(),
                        line_number,
                        name
                    );
                }
            }

            let object = normalize_object(row.object, path, line_number)?;
            let storage = match row.storage {
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
            if row.section != storage.pe_section() {
                anyhow::bail!(
                    "{}:{}: storage does not match PE section",
                    path.display(),
                    line_number
                );
            }

            let rva = parse_number(row.rva)?;
            let size = parse_number(row.size)?;
            if size == 0 || rva.checked_add(size).is_none() {
                anyhow::bail!(
                    "{}:{}: contribution extent must be non-empty and non-overflowing",
                    path.display(),
                    line_number
                );
            }
            let segment = parse_number(row.segment)?;
            if segment == 0 || segment > usize::from(u16::MAX) {
                anyhow::bail!(
                    "{}:{}: segment must fit a non-zero u16",
                    path.display(),
                    line_number
                );
            }

            contributions.push(Contribution {
                object,
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
            if pair[0].rva + pair[0].size > pair[1].rva {
                anyhow::bail!(
                    "{}: overlapping contribution intervals at RVA {:#x} and {:#x}",
                    path.display(),
                    pair[0].rva,
                    pair[1].rva
                );
            }
        }
        Ok(Self { contributions })
    }

    #[cfg(test)]
    pub(crate) fn from_manifest_bytes(bytes: &[u8]) -> Self {
        Self::parse(bytes, Path::new("test.tsv")).unwrap()
    }

    fn containing(&self, rva: usize) -> Option<&Contribution> {
        let index = self
            .contributions
            .partition_point(|contribution| contribution.rva <= rva);
        let contribution = self.contributions.get(index.checked_sub(1)?)?;
        (rva - contribution.rva < contribution.size).then_some(contribution)
    }

    /// Whether a symbol may represent a reference to `target_rva`.
    ///
    /// Both addresses must fall in one compiland's contribution of one storage
    /// class. Comparing storage keeps a compiland's own `.data` and `.bss`
    /// apart: they share a PE section but become separate COFF sections.
    ///
    /// An address the manifest does not cover constrains nothing, so an absent
    /// or partial manifest leaves symbol selection exactly as it was.
    pub fn same_owner(&self, symbol_rva: usize, target_rva: usize) -> bool {
        let Some(target) = self.containing(target_rva) else {
            return true;
        };
        self.containing(symbol_rva).is_some_and(|symbol| {
            symbol.storage == target.storage && symbol.object == target.object
        })
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

    fn manifest() -> ContributionManifest {
        ContributionManifest::parse(MANIFEST, Path::new("test.tsv")).unwrap()
    }

    #[test]
    fn constrains_symbols_to_the_owning_compiland() {
        let manifest = manifest();
        assert!(manifest.same_owner(0x101, 0x11f));
        assert!(!manifest.same_owner(0x101, 0x120));
        assert!(manifest.same_owner(0x120, 0x13f));
    }

    #[test]
    fn uncovered_addresses_constrain_nothing() {
        let manifest = manifest();
        assert!(manifest.same_owner(0x99, 0x99));
        assert!(manifest.same_owner(0x101, 0x1000));
        assert!(ContributionManifest::default().same_owner(0x101, 0x120));
    }

    #[test]
    fn an_uncovered_symbol_cannot_own_a_covered_target() {
        assert!(!manifest().same_owner(0xff, 0x100));
    }

    #[test]
    fn storage_classes_do_not_alias() {
        let manifest = manifest();
        assert!(!manifest.same_owner(0x200, 0x300));
        assert!(!manifest.same_owner(0x300, 0x200));
        assert!(manifest.same_owner(0x300, 0x30f));
    }

    #[test]
    fn resolves_interval_boundaries() {
        let manifest = manifest();
        assert!(manifest.same_owner(0x100, 0x11f));
        assert!(!manifest.same_owner(0x11f, 0x120));
        assert!(manifest.same_owner(0x120, 0x13f));
        // An interval ends before its last address, so 0x140 belongs to nobody.
        assert!(manifest.same_owner(0x120, 0x140));
    }

    #[test]
    fn rejects_overlapping_intervals() {
        let bytes = [
            MANIFEST,
            b"SOURCE\\BAD.c\trdata\t0x110\t0x20\t2\t.rdata\ttest\n",
        ]
        .concat();
        let error = ContributionManifest::parse(&bytes, Path::new("test.tsv"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlapping contribution intervals"));
    }

    #[test]
    fn rejects_storage_section_mismatch() {
        let bytes = b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\tbss\t0x100\t0x20\t2\t.rdata\ttest\n";
        let error = ContributionManifest::parse(bytes, Path::new("test.tsv"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("storage does not match PE section"));
    }

    #[test]
    fn rejects_malformed_rows() {
        for (bytes, expected) in [
            (
                &b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\trdata\t0x100\t0x20\t2\t.rdata\n"[..],
                "seven tab-separated columns",
            ),
            (
                &b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\trdata\t0x100\t0\t2\t.rdata\ttest\n"[..],
                "extent must be non-empty",
            ),
            (
                &b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\trdata\t0x100\t0x20\t0\t.rdata\ttest\n"[..],
                "segment must fit a non-zero u16",
            ),
            (
                &b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
c:\\SOURCE\\BAD.c\trdata\t0x100\t0x20\t2\t.rdata\ttest\n"[..],
                "must be relative and normalized",
            ),
            (
                &b"object\tstorage\trva\tsize\tsegment\tsection\tprovenance\n\
SOURCE\\BAD.c\ttls\t0x100\t0x20\t2\t.rdata\ttest\n"[..],
                "unsupported storage tls",
            ),
            (b"# no header\n", "missing contribution manifest header"),
        ] {
            let error = ContributionManifest::parse(bytes, Path::new("test.tsv"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(expected),
                "{error} should contain {expected}"
            );
        }
    }
}
