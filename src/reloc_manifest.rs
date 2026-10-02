use crate::manifest_tsv::{self, column, field};

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] = b"site_rva\tkind";

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
        let ((), rows) = manifest_tsv::read(bytes, path, "reloc manifest", &[(HEADER, ())])?;
        for row in rows {
            let (site_rva, kind) = row.columns((column, field), "two")?;
            if kind != b"dir32" {
                anyhow::bail!("{row}: unsupported kind {}", String::from_utf8_lossy(kind));
            }
            let site_rva = row.number("site_rva", site_rva)?;
            if !seen.insert(site_rva) {
                anyhow::bail!("{row}: duplicate site RVA");
            }
            sites.push(site_rva);
        }
        sites.sort_unstable();
        Ok(Self { sites })
    }

    /// The reviewed site RVAs, ascending.
    pub fn sites(&self) -> &[usize] {
        &self.sites
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
