use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] = b"site_rva\tkind";

struct RelocRow<'a> {
    site_rva: &'a [u8],
    kind: &'a [u8],
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

fn manifest_row(input: &[u8]) -> IResult<&[u8], RelocRow<'_>> {
    let (input, (site_rva, kind)) = (terminated(field, tag(&b"\t"[..])), field).parse(input)?;
    Ok((input, RelocRow { site_rva, kind }))
}

/// Reviewed list of absolute (`dir32`) relocation sites, for an image whose
/// `.reloc` directory is missing. Each row names the RVA of a 4-byte field that
/// holds a linked target address; the delinker reads and classifies the target
/// (see `relocs::resolve_absolute_site`), so the manifest need only locate the
/// sites the `.reloc` directory would have listed.
#[derive(Debug)]
pub struct RelocManifest {
    sites: Vec<usize>,
}

impl RelocManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Option<Self>> {
        let Some(path) = path else {
            return Ok(None);
        };
        Ok(Some(Self::parse(&std::fs::read(path)?, path)?))
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let mut sites = Vec::new();
        let mut seen = HashSet::new();
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
                        "{}:{}: invalid reloc manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            if line == HEADER {
                anyhow::bail!(
                    "{}:{}: duplicate reloc manifest header",
                    path.display(),
                    line_number
                );
            }

            let (_, row) = all_consuming(manifest_row).parse(line).map_err(|_| {
                anyhow::anyhow!(
                    "{}:{}: expected exactly two tab-separated columns",
                    path.display(),
                    line_number
                )
            })?;
            match row.kind {
                b"dir32" => {}
                value => anyhow::bail!(
                    "{}:{}: unsupported kind {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(value)
                ),
            }
            let site_rva = parse_number(row.site_rva).ok_or_else(|| {
                anyhow::anyhow!("{}:{}: invalid site_rva", path.display(), line_number)
            })?;
            if !seen.insert(site_rva) {
                anyhow::bail!("{}:{}: duplicate site RVA", path.display(), line_number);
            }
            sites.push(site_rva);
        }

        if !saw_header {
            anyhow::bail!("{}: missing reloc manifest header", path.display());
        }
        sites.sort_unstable();
        Ok(Self { sites })
    }

    /// The reviewed site RVAs, ascending.
    pub fn sites(&self) -> &[usize] {
        &self.sites
    }
}

fn parse_number(value: &[u8]) -> Option<usize> {
    let value = std::str::from_utf8(value).ok()?;
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => usize::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> anyhow::Result<RelocManifest> {
        RelocManifest::parse(body.as_bytes(), Path::new("test.tsv"))
    }

    #[test]
    fn absent_manifest_is_none() {
        assert!(RelocManifest::load(None).unwrap().is_none());
    }

    #[test]
    fn parses_comments_crlf_and_sorts() {
        let text = concat!(
            "# reviewed relocations\r\n",
            "site_rva\tkind\r\n",
            "0x140\tdir32\r\n",
            "\r\n",
            "0X100\tdir32\r\n",
            "288\tdir32\r\n",
        );
        assert_eq!(parse(text).unwrap().sites(), &[0x100, 0x120, 0x140]);
    }

    #[test]
    fn rejects_missing_and_duplicate_headers() {
        assert!(
            parse("0x100\tdir32\n")
                .unwrap_err()
                .to_string()
                .contains("invalid reloc manifest header")
        );
        assert!(
            parse("# only a comment\n")
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
        assert!(
            parse("site_rva\tkind\nsite_rva\tkind\n")
                .unwrap_err()
                .to_string()
                .contains("duplicate reloc manifest header")
        );
    }

    #[test]
    fn rejects_wrong_columns_kind_and_duplicate_site() {
        let hdr = "site_rva\tkind\n";
        assert!(
            parse(&format!("{hdr}0x100\n"))
                .unwrap_err()
                .to_string()
                .contains("exactly two")
        );
        assert!(
            parse(&format!("{hdr}0x100\tdir32\textra\n"))
                .unwrap_err()
                .to_string()
                .contains("exactly two")
        );
        assert!(
            parse(&format!("{hdr}0x100\trel32\n"))
                .unwrap_err()
                .to_string()
                .contains("unsupported kind")
        );
        assert!(
            parse(&format!("{hdr}zz\tdir32\n"))
                .unwrap_err()
                .to_string()
                .contains("invalid site_rva")
        );
        assert!(
            parse(&format!("{hdr}0x100\tdir32\n0x100\tdir32\n"))
                .unwrap_err()
                .to_string()
                .contains("duplicate site RVA")
        );
    }
}
