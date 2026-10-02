use crate::manifest_tsv::{self, column, field};

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] = b"object\tname\tsize";

/// An uninitialized global that an object declares COMMON: it owns no section
/// bytes, and the linker allocates the largest size any object asks for.
#[derive(Clone, Copy, Debug)]
pub struct CommonSymbol {
    pub object: &'static [u8],
    pub name: &'static [u8],
    pub size: u64,
}

#[derive(Default)]
pub struct CommonSymbolManifest {
    symbols: Vec<CommonSymbol>,
}

impl CommonSymbolManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let ((), rows) =
            manifest_tsv::read(bytes, path, "COMMON symbol manifest", &[(HEADER, ())])?;
        let mut symbols = Vec::new();
        let mut seen = HashSet::new();
        for row in rows {
            let (object, name, size) = row.columns((column, column, field), "three")?;
            let object = row.object(object)?;
            row.non_empty_text("COMMON symbol name", name)?;
            let size = row.number("size", size)? as u64;
            if size == 0 {
                anyhow::bail!("{row}: COMMON symbol size must be non-zero");
            }
            let name: &'static [u8] = name.to_vec().leak();
            if !seen.insert((object, name)) {
                anyhow::bail!(
                    "{row}: duplicate COMMON symbol {} in {}",
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(object)
                );
            }
            symbols.push(CommonSymbol { object, name, size });
        }
        Ok(Self { symbols })
    }

    pub fn symbols(&self) -> &[CommonSymbol] {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> anyhow::Result<CommonSymbolManifest> {
        CommonSymbolManifest::parse(text.as_bytes(), Path::new("common.tsv"))
    }

    #[test]
    fn parses_rows_per_object() {
        let manifest = parse(
            "# generated\nobject\tname\tsize\nSOURCE/A.c\t_gGuard\t1\nSOURCE/B.c\t_gGuard\t0x4\n",
        )
        .unwrap();
        let symbols = manifest.symbols();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].object, b"SOURCE\\A.c");
        assert_eq!((symbols[1].name, symbols[1].size), (&b"_gGuard"[..], 4));
    }

    #[test]
    fn rejects_malformed_rows() {
        for (rows, error) in [
            ("a.c\tx\t0\n", "non-zero"),
            ("a.c\t\t4\n", "non-empty"),
            ("C:\\a.c\tx\t4\n", "relative"),
            ("a.c\tx\n", "three"),
            ("a.c\tx\t4\na.c\tx\t8\n", "duplicate COMMON symbol x"),
        ] {
            let message = parse(&format!("object\tname\tsize\n{rows}"))
                .err()
                .unwrap()
                .to_string();
            assert!(message.contains(error), "{rows:?}: {message}");
        }
        assert!(parse("name\tsize\n").is_err());
    }
}
